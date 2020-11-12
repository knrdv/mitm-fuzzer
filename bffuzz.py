""" Fuzzing addon for mitmproxy

This mitmproxy addon implements simple fuzzing functionality for POST forms.
Usage: Choose one parameter in the fuzz as: 'fuzz_DBNAME' where DBNAME is 
the list of fuzz inputs contained inside a file in the DBS_DIR.
"""
from mitmproxy import ctx
from mitmproxy import http
from mitmproxy import command
import mitmproxy.addonmanager
import logging
from attack import POSTAttack, GETAttack
import config

logger = logging.getLogger("bffuzz")
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(config.LOGFILE)
formatter = logging.Formatter("%(name)s:%(levelname)s:%(message)s")
fh.setFormatter(formatter)
logger.addHandler(fh)
open(config.LOGFILE, "w").close()

class BFFuzz:
	"""A class with purpose of detection of attack-trigger parameters."""

	def __init__(self):
		self.host_monitors: list = []
		self.host_filter_string = ["~d"]
		self.attack = None
		self.trigger_string = None
		self.invert_attack = False

	def detectFuzzParams(self, flow: http.HTTPFlow) -> bool:
		"""Checks POST request for trigger parameters."""

		if flow.request.method == "POST":
			parameters = flow.request.urlencoded_form
		elif flow.request.method == "GET":
			parameters = flow.request.query
		else:
			logger.warning("Triggering parameters not detected in the request.")
		fuzz = False
		for parameter in parameters:
			if parameters[parameter].startswith(config.PARAMETER_PREFIX):
				fuzz = True
				logger.info("BFFuzz: Trigger parameters detected")
				break
		return fuzz

	def setAttackMode(self):
		"""Sets attack mode to inverted or not inverted."""

		if not self.attack:
			logger.error("Attack object not instantiated")
			return
		if not self.trigger_string:
			logger.error("Set a trigger string usin commands")
			return
		self.attack.setSuccessString(self.trigger_string, self.invert_attack)


# MITM COMMANDS

	@command.command("bffuzz.subscribe")
	def subscribe(self, host: str) -> None:
		"""Adds host to the list of monitored hosts."""

		self.host_monitors.append(host)
		self.host_filter_string.append(host)
		ctx.log.info("BFFuzz: successfully added new host monitor: " + host)
		ctx.master.commands.call("view.filter.set", ' '.join(self.host_filter_string))

	@command.command("bffuzz.settrigger")
	def settrigger(self, trigger_str: str, inverted: bool=False) -> None:
		"""Sets a string which determines a successful use of credentials."""
		
		self.trigger_string = trigger_str
		self.invert_attack = inverted
		logger.info("Triggering string set to: " + self.trigger_string + ", inverted:" + str(self.invert_attack))

# MITM EVENTS

	def load(self, entry: mitmproxy.addonmanager.Loader):
		"""Triggers after mitmproxy addon has been loaded."""

		ctx.log.info("BFFuzz: addon loaded successfully")

	def request(self, flow: http.HTTPFlow) -> None:
		"""Triggers an attack when correct parameters are detected."""

		if self.attack and self.attack.isRunning():
			self.attack.handleRequest(flow)
		elif flow.request.host in self.host_monitors:
			start_attack = self.detectFuzzParams(flow)
			logger.info("Got start attack:"+str(start_attack))
			if start_attack:
				if flow.request.method == "GET":
					self.attack = GETAttack(flow)
					self.setAttackMode()
					self.attack.start()

				elif flow.request.method == "POST":
					self.attack = POSTAttack(flow)
					self.setAttackMode()
					self.attack.start()


	def response(self, flow: http.HTTPFlow) -> None:
		"""Forwards responses."""

		if self.attack and self.attack.isRunning():
			self.attack.handleResponse(flow)

addons = [
	BFFuzz()
]
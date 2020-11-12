"""Success Detector Module

This class represents success detector
"""
import logging
from mitmproxy import http

logger = logging.getLogger("bffuzz")

class SuccessDetector:
	"""Detects expected responses for correct credentials"""

	def __init__(self, ss=None):
		self.last_credentials = None
		self.responses = []
		self.trigger_string = ss
		self.inverted_mode = False

	def insertResponse(self, flow: http.HTTPFlow) -> None:
		"""Inserts all received responses in a list for later processing."""

		if flow.response:
			self.responses.append(flow.response.copy())
		else:
			logger.error("Flow has no response, can't insert")

	def setCredentials(self, credentials: dict) -> None:
		"""Sets credentials."""

		self.last_credentials = credentials
		logger.info("Credentials set:" + str(credentials))

	def setSuccessString(self, trigger_string: str) -> None:
		"""Sets string indicating correct response."""

		self.trigger_string = trigger_string

	def setNotSuccessString(self, trigger_string: str) -> None:
		"""Set inverse trigger to given string."""

		self.trigger_string = trigger_string
		self.inverted_mode = True

	def delSuccessString(self):
		"""Sets suc.str. back to Null"""

		self.trigger_string = None


	def isSuccess(self, flow: http.HTTPFlow) -> dict:
		"""Detects if correct response is triggered."""

		result = None
		if not flow.response:
			logger.error("Flow has no response, can't perform detection")
		
		self.insertResponse(flow)

		if not self.inverted_mode:
			if self.trigger_string in flow.response.text:
				result = self.last_credentials
				logger.info("Trigger string in normal mode detected, last credentials:" + str(result))
			if self.trigger_string not in flow.response.text:
				result = self.last_credentials
				logger.info("Trigger string in inverted mode detected, last credentials:" + str(result))

		return result


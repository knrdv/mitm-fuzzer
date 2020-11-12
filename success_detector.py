"""Success Detector Module

This class represents success detector
"""
import logging
from mitmproxy import http

logger = logging.getLogger("formfuzz")

class SuccessDetector:
	"""Detects expected responses for correct credentials"""

	def __init__(self, ss=None):
		self.last_credentials = None
		self.responses = []
		self.success_string = ss

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

	def setSuccessString(self, success_string: str) -> None:
		"""Sets string indicating correct response."""

		self.success_string = success_string

	def delSuccessString(self):
		"""Sets suc.str. back to Null"""

		self.success_string = None


	def isSuccess(self, flow: http.HTTPFlow) -> dict:
		"""Detects if correct response is triggered."""

		result = None
		if not flow.response:
			logger.error("Flow has no response, can't perform detection")
		
		self.insertResponse(flow)

		if self.success_string in flow.response.text:
			result = self.last_credentials
			logger.info("SUCCESSFUL RESPONSE, last credentials:" + str(result))
		return result


import logging
from mitmproxy import http

logger = logging.getLogger("formfuzz")


class SuccessDetector:

	def __init__(self):
		self.last_credentials = None
		self.responses = []
		self.success_string = None
		logger.info("STARTED SUCCESS DETECTOR")

	def insertResponse(self, flow: http.HTTPFlow) -> None:
		if flow.response:
			self.responses.append(flow.response.copy())
		else:
			logger.error("Flow has no response, can't insert")

	def setCredentials(self, credentials: dict) -> None:
		self.last_credentials = credentials

	def setSuccessString(self, success_string: str) -> None:
		self.success_string = success_string


	def detector(self, flow: http.HTTPFlow) -> dict:
		result = None
		if not flow.response:
			logger.error("Flow has no response, can't perform detection")
		
		self.insertResponse(flow)

		if self.success_string in flow.response.text:
			logger.info("GREAT SUCCESS! FOUND CORRECT CREDENTIALS: " + str(self.last_credentials))
			result = self.last_credentials
		return result
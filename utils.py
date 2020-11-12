""" Utility class

Utility class which contains helper classes:
SuccessDetector: Checks if fuzz was successful.
Attack: Performs an attack.
"""
import logging
from mitmproxy import http
import os.path
from bs4 import BeautifulSoup
from mitmproxy import net
import tkinter as tk
from tkinter import messagebox

logger = logging.getLogger("bffuzz")

PARAMETER_PREFIX = "fuzz_"
PREFIX_LEN = len(PARAMETER_PREFIX)
DBS_DIR = "./dbs/"

def loadPathToList(file_path: str) -> list:
	"""Loads content from path file to a list"""

	content_list = []
	if not os.path.exists(file_path):
		logger.warning("Path " + file_path + " for parameter " + parameter + " does not exist")
	with open(file_path, "r") as f:
		content_list = [x.strip() for x in f]
	return content_list

def extractCSRF(flow: http.HTTPFlow) -> str:
	"""Extracts CSRF token from HTTP GET response"""

	if not flow.response:
		logger.error("Trying to extract token from an empty response")
		return
	if not flow.request.method == "GET":
		logger.error("Trying to extract token from a response which isn't GET")
		return
	parsed_html = BeautifulSoup(flow.response.content, features="html.parser")
	parsed_body = parsed_html.body.find("input", attrs={"name":"user_token"})
	logger.info("Parsed body:"+str(parsed_body))
	csrf_token = None
	if parsed_body:
		csrf_token = parsed_body.get("value")
	logger.info("Extracted CSRF token:" + str(csrf_token))
	return csrf_token


def getRequestParams(request: net.http.request) -> dict:
	if request.method == "GET":
		return request.query
	elif request.method == "POST":
		return request.urlencoded_form
	else:
		logger.error("When trying to get parameters from request: method not recognized")


def setFlowRequestParameter(flow, param, val):
	"""Sets next parameter depending on POST or GET request"""

	if not flow.request: 
		logger.error("This is not a flow request, can't set parameter")
		return
	if flow.request.method == "GET":
		flow.request.query[param] = val
	elif flow.request.method == "POST":
		flow.request.urlencoded_form[param] = val
	else:
		logger.error("This flow contains neither a GET or POST request")
		return

def prettyPrintDict(d: dict) -> str:
	retstr = ""
	for key, value in d.items():
		retstr += key + ": " + value + "\n"
	return retstr

def showMessage(title: str, msg: str) -> None:
	window = tk.Tk()
	if messagebox.showinfo(title, msg):
		window.destroy()
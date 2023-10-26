from flask import Flask, render_template, request, flash, url_for, redirect, Response, jsonify
import json
import datetime
import time
from collections import OrderedDict
import openai
import os
import requests
import virustotal_python
from pprint import pprint
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet

my_secret = b'gAAAAABlOWsN0ZQVTqXuSoyzCyHQ_7G9OogPBtSK4tmn5EdCHBAyP5dgqnIEuIZEf4ELTGEOH5-4wAoZmGmKeuMIsq4s1K9YVppRpthYh-FWX4hyZWYjk5LuwPrCPxY6MSEmuFGC_A4rsMkYabkOa856NTbFlhSMdg=='
total_key = b'gAAAAABlOWsNTAl0Cpb3whFklRLHojB5U9sQJd3uDzmfOJNxLXeBN6Skxl1ucIxYEo-ZRaMm-WzPWDJOq2lDQKSGis-BDpp0K2OL58guQfhDOw4SBWsQoSZPWgA6tSlJRwUwDvb_vUxAdZ6ZyRm1SnmrF5TcHVLbohV7NMG9YFd2ZA-OYotGgho='
key = b'IIhPfBLQ8edgQXPpSgAuBKkrlmD7BYWHgA3Zj5zqx6g='

f = Fernet(key)
my_secret = f.decrypt(my_secret).decode()
total_key = f.decrypt(total_key).decode()

app = Flask(__name__)
app.secret_key = "abc"
API_KEY = total_key


def check_url(url):
  with virustotal_python.Virustotal(API_KEY) as vtotal:
    try:
      resp = vtotal.request("urls", data={"url": url}, method="POST")

      url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
      report = vtotal.request(f"urls/{url_id}")

      output = report.data['attributes']['last_analysis_stats']
      n = 0
      for i in report.data['attributes']['last_analysis_stats']:
        print(report.data['attributes']['last_analysis_stats'][i])
        n += report.data['attributes']['last_analysis_stats'][i]

      if output['malicious'] > 0:
        output = "malicious"
      elif output['suspicious'] > 5:
        output = "suspicious"
      else:
        output = "clean"
      output = f"""{url} is \n {output}, checked using {n} antivirus services"""
      return output

    except virustotal_python.VirustotalError as err:
      output = f"Failed to send URL: {url} for analysis and get the report: {err}"
    return output


def generate_chat_reply(prompt):

  openai.api_key = my_secret
  response = openai.ChatCompletion.create(model="gpt-3.5-turbo",
                                          messages=[{
                                              "role": "user",
                                              "content": prompt
                                          }])

  return response.choices[0].message.content


@app.route("/tips", methods=["GET", "POST"])
def tip():
  if request.method == "POST":
    if request.form.get("Submit") == "Submit":
      prompt = request.form.get("Prompt")
      reply = generate_chat_reply(f"""generate a safety tip based on- 
      {prompt}""")

      flash(reply)

  return render_template("tips.html")


@app.route('/url', methods=["GET", "POST"])
def website_scan():
  if request.method == "POST":
    if request.form.get("Submit") == "Submit":
      url = request.form.get("url")
      reply = check_url(url)

      flash(f"{reply}")

  return render_template("url.html")


@app.route("/", methods=["GET", "POST"])
def home():
  if request.method == "POST":
    if request.form.get("Tips") == "Tips":
      return render_template("tips.html")
    if request.form.get("Analyse File") == "Analyse File":
      return render_template("check.html")
    if request.form.get("Check Now") == "Check Now":

      return render_template("url.html")
    if request.form.get("Report Now") == "Report Now":
      return render_template("report.html")
  return render_template("home.html")


if __name__ == '__main__':
  app.run(port=8080, host="0.0.0.0", debug=True)

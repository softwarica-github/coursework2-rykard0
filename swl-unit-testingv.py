import unittest
import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin

# Define functions from your original script
def get_all_forms(url):
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    action = form.attrs.get("action")
    if action is not None:
        action = action.lower()

    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def is_vulnerable(response):
    errors = {
        "you have an error in your sql syntax;",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
    }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False

# Define unit tests
class TestSQLInjectionScanner(unittest.TestCase):

    def test_get_all_forms(self):
        forms = get_all_forms("http://localhost:8888/vulnerabilities/sqli/")
        self.assertTrue(forms)


    def test_get_form_details(self):
        sample_form = bs('<form action="/submit" method="post"><input type="text" name="username"></form>', 'html.parser')
        form_details = get_form_details(sample_form)

        expected_action = "/submit"
        expected_method = "post"
        expected_inputs = [{"type": "text", "name": "username", "value": ""}]


    def test_is_vulnerable(self):
        vulnerable_response = requests.Response()
        vulnerable_response._content = b"you have an error in your sql syntax;"
        self.assertTrue(is_vulnerable(vulnerable_response))

        non_vulnerable_response = requests.Response()
        non_vulnerable_response._content = b"this is a normal response"
        self.assertFalse(is_vulnerable(non_vulnerable_response))

if __name__ == "__main__":
    unittest.main()


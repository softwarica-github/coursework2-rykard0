import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin

# Function to extract all forms from the HTML content
def get_all_forms(url):
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")

# Function to extract form details like action, method, and input fields
def get_form_details(form):
    details = {}
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
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

# Function to check if a page is SQL Injection vulnerable from its response
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

# Function to test for SQL injection vulnerability in a URL and its forms
def scan_sql_injection(url):
    # Test on URL
    for c in "\"'":
        new_url = f"{url}{c}"
        print("[!] Trying injection on", new_url)
        res = requests.get(new_url)
        if is_vulnerable(res):
            print("[+] SQL Injection vulnerability detected, link:", new_url)
            return

    # Test on HTML forms
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on URL.")
    print("[+] Possible SQL injection Vulnrability.")
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{c}"

            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = requests.post(url, data=data)
            elif form_details["method"] == "get":
                res = requests.get(url, params=data)
            if is_vulnerable(res):
                print("[+] SQL Injection vulnerability detected, link:", url)
                print("[+] Form:")
                print(form_details)
                break

if __name__ == "__main__":
    url = input("Enter the URL to check for SQL injection: ")
    scan_sql_injection(url)

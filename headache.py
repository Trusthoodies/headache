from headers import *
from helpers import Helpers
import requests, json, pandas, argparse

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-dl", "--domainlist", help="list of domains.")
    parser.add_argument("-w", "--writehtml", help="Convert output to an HTML table and write to a file.")
    parser.add_argument("-i", "--issues", help="Show what issue a specific directive has.", action='store_true')
    args = parser.parse_args()
    
    return args

def fetch_headers(domain_list):
    for domain in domain_list:
        headers = {}
        domain = Helpers.parse_domain(domain)

        response = requests.get(domain, allow_redirects=True)
        resp_headers = dict((k.lower(), v.lower()) for k,v in response.headers.items())

        headers["domain"] = domain
        headers["headers"] = resp_headers

        fetched_headers.append(headers)

def verify_headers():
    for header_dict in fetched_headers:
        domain = header_dict['domain']
        all_headers = header_dict["headers"]
        temp_dict = {"domain" : domain}

        for sec_header in Helpers.security_headers:
            if sec_header not in header_dict['headers']:
                temp_dict[sec_header] = "Absent"
            else:
                if sec_header in ["content-security-policy", "strict-transport-security"]:
                    Helpers.is_insufficient(domain, all_headers, temp_dict, sec_header)
                else:
                    temp_dict[sec_header] = "Present"

        verified_headers.append(temp_dict)

def convert_to_html_table(write_location):
    df = pandas.DataFrame.from_dict(verified_headers)
    table = df.to_html(index=False, table_id="tbl")
    table = table.replace("<td>Insufficient</td>","<td class='insufficient'>Insufficient</td>")
    table = table.replace("<td>Absent</td>","<td class='false'>Absent</td>")
    table = table.replace("<td>Present</td>", "<td class='true'>Present</td>")
    # https://www.w3schools.com/css/tryit.asp?filename=trycss_table_fancy
    css = """
    <style>
    .true {
        color: green;
    }
    .insufficient {
        color: orange;
    }
    .false {
        color: red;
    }
    #tbl {
        font-family: Arial, Helvetica, sans-serif;
        border-collapse: collapse;
        width: 100%;
    }
    #tbl td, #tbl th {
        border: 1px solid #ddd;
        padding: 8px;
    }
    #tbl tr:nth-child(even){background-color: #f2f2f2;}
    #tbl tr:hover {background-color: #ddd;}
    #tbl th {
        padding-top: 12px;
        padding-bottom: 12px;
        text-align: left;
        background-color: #04AA6D;
        color: white;
    }
    </style>
    """
    pretty_table = css + table

    if write_location:
        print(f"[+] Writing output to {write_location}")
        f = open(write_location, "w")
        f.write(pretty_table)
        f.close()


def show_output(show_issues):
    if show_issues:
        print(json.dumps(issues_list))
    print(json.dumps(verified_headers))

def main():
    args = parse_arguments()
    domain_list = open(args.domainlist, "r")
    write_location = args.writehtml
    show_issues = args.issues

    fetch_headers(domain_list)
    verify_headers()
    convert_to_html_table(write_location)
    show_output(show_issues)

main()

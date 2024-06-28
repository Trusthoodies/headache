from variables import *
from helpers import Helpers
import requests, json, pandas, argparse, threading

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-dl", "--domainlist", help="list of domains.")
    parser.add_argument("-d", "--domain", help="domain")
    parser.add_argument("-w", "--writehtml", help="Convert output to an HTML table and write it to a file.")
    parser.add_argument("-i", "--issues", help="Show what issue made a header insufficient.", action='store_true')
    parser.add_argument("-is", "--ignore", help="Ignore ssl errors.", action='store_true')
    parser.add_argument("-r", "--redirect", help="Follow redirects.", action='store_true')
    parser.add_argument("-ua", "--useragent", help="Set User-Agent")
    args = parser.parse_args()
    
    return args

def fetch_headers(domain, ignore_ssl, redirect, user_agent):
    headers = {}
    user_agent_header = {"user-agent" : user_agent} if user_agent else {}
    
    try:
        response = requests.get(domain, allow_redirects=redirect, verify=not ignore_ssl, headers=user_agent_header)
    except:
        issue = {"domain" : domain, "issues" : "Couldn't reach domain"}
        issues_list.append(issue)
        return
    
    resp_headers = dict((k.lower(), v.lower()) for k,v in response.headers.items())

    headers["domain"] = domain
    headers["headers"] = resp_headers

    fetched_headers.append(headers)

def verify_headers():
    for header_dict in fetched_headers:
        domain = header_dict['domain']
        all_headers = header_dict["headers"]
        temp_dict = {"domain" : domain}

        for sec_header in security_headers:
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
    pretty_table = css + table

    print(f"\"[+] Writing output to {write_location}\"")

    f = open(write_location, "w")
    f.write(pretty_table)
    f.close()

def show_output(show_issues):
    if show_issues:
        print(json.dumps(issues_list))
    print(json.dumps(verified_headers))

def fetch_headers_threaded(domain_list, ignore_ssl, redirect, user_agent):
    threads = []
    if type(domain_list) == list:
        domain_list = Helpers.parse_list(domain_list)

        for domain in domain_list:
            t = threading.Thread(target=fetch_headers, args=(domain, ignore_ssl, redirect, user_agent,))
            t.daemon = True
            threads.append(t)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()
    else:
        fetch_headers(domain_list, ignore_ssl, redirect, user_agent)


def main():
    args = parse_arguments()
    if args.domain and args.domainlist:
        print("[!] Kies tussen een lijst of single domain.")

    if args.domainlist:
        domain_list = open(args.domainlist, "r")
    else:
        domain_list = args.domain
    ignore_ssl = args.ignore
    write_location = args.writehtml
    redirect = args.redirect
    show_issues = args.issues
    user_agent = args.useragent
    
    # domain_list = open("test3", "r")
    # write_location = None
    # ignore_ssl = False
    # show_issues = True
    # redirect = True
    # user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:102.0) Gecko/20100101 Firefox/102.0"

    #fetch_headers(domain_list, ignore_ssl, redirect)
    fetch_headers_threaded(domain_list, ignore_ssl, redirect, user_agent)
    verify_headers()
    show_output(show_issues)
    
    if write_location:
        convert_to_html_table(write_location)

if __name__ == "__main__":
    main()

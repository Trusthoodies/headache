import requests, json, re, pandas, argparse

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-dl", "--domainlist", help="list of domains")
    parser.add_argument("-w", "--writefile", help="write to file instead of printing it to the screen")
    args = parser.parse_args()
    
    return args


security_headers = [
    "content-security-policy",
    "x-content-type-options",
    "strict-transport-security",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy"
]

absent_headers = []

def inadequate_csp(domain, header):
    header = header.replace(" ","")
    script_src_val = re.search("script-src[^;]+", header)[0]
    unsafe_keywords = ["unsafe-eval", "unsafe-inline", "*", "data"]

    if any(ele in script_src_val for ele in unsafe_keywords):
        print(f"[!] {domain} bevat onveilige CSP waarden.")
        return True
    
    return False

def inadequate_hsts(domain, header):
    min_age = 10368000
    max_age_val = int(re.search('max-age=(\d+);?', header)[1])

    if "includesubdomains" not in header:
        print(f"[!] {domain}: mist includeSubDomains")
        return True
    elif max_age_val < min_age:
        print(f"[!] {domain}: Max-age is korter dan 10368000<br>")
        return True

    return False

def fetch_headers(domains):
    """ Fetches all response headers from all domains, and checks what headers are not in the security_headers list """

    for domain in domains:
        domain = domain[:-1]
        temp_dict = {"domain" : domain}
        domain = domain if domain[:4] == "http" else "https://" + domain
        try:
            response = requests.get(domain, allow_redirects = True) #verify=False
            response_headers = dict((k.lower(), v.lower()) for k,v in response.headers.items())

            for sec_header in security_headers:
                if sec_header not in response_headers:
                    temp_dict[sec_header] = False
                else:
                    if sec_header == "content-security-policy":
                        value_csp = response_headers[sec_header]

                        if inadequate_csp(domain, value_csp):
                            temp_dict[sec_header] = "Onvoldoende"
                        else:
                            temp_dict[sec_header] = True
                    elif sec_header == "strict-transport-security":
                        value_hsts = response_headers[sec_header]

                        if inadequate_hsts(domain,value_hsts):
                            temp_dict[sec_header] = "Onvoldoende"
                        else:
                            temp_dict[sec_header] = True
                    else:
                        temp_dict[sec_header] = True

            absent_headers.append(temp_dict)
        # https://stackoverflow.com/questions/16511337/correct-way-to-try-except-using-python-requests-module
        except requests.exceptions.HTTPError as errh:
            print ("Http Error:",errh)
        except requests.exceptions.ConnectionError as errc:
            print ("Probleem met verbinding:",errc)
        except requests.exceptions.Timeout as errt:
            print ("Timeout Error:",errt)
        except requests.exceptions.RequestException as err:
            print ("Iets ging verkeerd, geen idee wat:",err)


def convert_to_html(write_to_file=False):
    """ Converts the  dictionary to a nice HTML table """
    json_absent_headers = json.dumps(absent_headers)
    df = pandas.read_json(json_absent_headers)

    table = df.to_html(index=False, table_id="tbl")
    table = table.replace("<td>Onvoldoende</td>","<td class='onvoldoende'>Onvoldoende</td>")
    table = table.replace("<td>False</td>","<td class='false'>False</td>")
    table = table.replace("<td>True</td>", "<td class='true'>True</td>")
    # https://www.w3schools.com/css/tryit.asp?filename=trycss_table_fancy
    css = """
    <style>
    .true {
        color: green;
    }
    .onvoldoende {
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
    
    if write_to_file:
        file = open(write_to_file,"w")
        file.write(pretty_table)
        file.close()
    else:
        print(pretty_table)

def main():
    args = parse_arguments()
    domains = open(args.domainlist, "r")
    fetch_headers(domains)
    convert_to_html(args.writefile)

if __name__ == "__main__":
    main()

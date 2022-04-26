import re
from variables import issues_list

class Helpers:
    security_headers = [
        "content-security-policy",
        "x-content-type-options",
        "strict-transport-security",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy"
    ]

    @staticmethod
    def is_insufficient(domain, headers, temp, directive):
        issues = []

        if directive == "content-security-policy":
            header = headers[directive]
            unsafe_csp_keywords = ["unsafe-eval", "unsafe-inline", "*", "data"]
            try:
                csp_val = re.search("script-src[^;]+", header)[0]
                if any(ele in csp_val for ele in unsafe_csp_keywords):
                    issues.append("CSP contains dangerous keywords.")
                    temp[directive] = "Insufficient"
                else:
                    temp[directive] = "Present"
            except:
                issues.append("script-src directive is missing.")
                temp[directive] = "Insufficient"

        elif directive == "strict-transport-security":
            header = headers[directive]
            min_age = 10368000
            max_age_val = int(re.search('max-age=(\d+);?', header)[1])

            if "includesubdomains" not in header:
                temp[directive] = "Insufficient"
                issues.append("Missing IncludeSubDomains")
            if max_age_val < min_age:
                temp[directive] = "Insufficient"
                issues.append("Max-age is shorter than 10368000")
            if "includesubdomains" in header and max_age_val >= min_age:
                temp[directive] = "Present"

        if issues:
            issues_dict = {"domain" : domain}
        
            issues_dict["issues"] = issues
            issues_list.append(issues_dict)

    @staticmethod
    def parse_domain(domain):
        domain = domain.strip()
        domain = domain if domain[:4] == "http" else "https://" + domain

        return domain
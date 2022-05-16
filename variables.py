fetched_headers = []
verified_headers = []
issues_list = []
security_headers = [
    "content-security-policy",
    "x-content-type-options",
    "strict-transport-security",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy"
]
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
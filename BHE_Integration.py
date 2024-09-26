import requests
import json
import hmac
import hashlib
import base64
import requests
import sys

from datetime import datetime
from typing import Optional

class Credentials(object):
    def __init__(self, token_id: str, token_key: str) -> None:
        self.token_id = token_id
        self.token_key = token_key


class APIVersion(object):
    def __init__(self, api_version: str, server_version: str) -> None:
        self.api_version = api_version
        self.server_version = server_version


class Domain(object):
    def __init__(self, name: str, sid: str, collected: bool) -> None:
        self.name = name
        self.sid = sid
        self.collected = collected


class Client(object):
    def __init__(self, scheme: str, host: str, port: int, credentials: Credentials) -> None:
        self._scheme = scheme
        self._host = host
        self._port = port
        self._credentials = credentials

    def _format_url(self, uri: str) -> str:
        formatted_uri = uri
        if uri.startswith("/"):
            formatted_uri = formatted_uri[1:]

        return f"{self._scheme}://{self._host}:{self._port}/{formatted_uri}"

    def _request(self, method: str, uri: str, body: Optional[bytes] = None) -> requests.Response:
        # Digester is initialized with HMAC-SHA-256 using the token key as the HMAC digest key.
        digester = hmac.new(self._credentials.token_key.encode(), None, hashlib.sha256)

        # OperationKey is the first HMAC digest link in the signature chain. This prevents replay attacks that seek to
        # modify the request method or URI. It is composed of concatenating the request method and the request URI with
        # no delimiter and computing the HMAC digest using the token key as the digest secret.
        #
        # Example: GET /api/v1/test/resource HTTP/1.1
        # Signature Component: GET/api/v1/test/resource
        digester.update(f"{method}{uri}".encode())

        # Update the digester for further chaining
        digester = hmac.new(digester.digest(), None, hashlib.sha256)

        # DateKey is the next HMAC digest link in the signature chain. This encodes the RFC3339 formatted datetime
        # value as part of the signature to the hour to prevent replay attacks that are older than max two hours. This
        # value is added to the signature chain by cutting off all values from the RFC3339 formatted datetime from the
        # hours value forward:
        #
        # Example: 2020-12-01T23:59:60Z
        # Signature Component: 2020-12-01T23
        datetime_formatted = datetime.now().astimezone().isoformat("T")
        digester.update(datetime_formatted[:13].encode())

        # Update the digester for further chaining
        digester = hmac.new(digester.digest(), None, hashlib.sha256)

        # Body signing is the last HMAC digest link in the signature chain. This encodes the request body as part of
        # the signature to prevent replay attacks that seek to modify the payload of a signed request. In the case
        # where there is no body content the HMAC digest is computed anyway, simply with no values written to the
        # digester.
        if body is not None:
            digester.update(body)

        # Perform the request with the signed and expected headers
        return requests.request(
            method=method,
            url=self._format_url(uri),
            headers={
                "User-Agent": "bhe-python-sdk 0001",
                "Authorization": f"bhesignature {self._credentials.token_id}",
                "RequestDate": datetime_formatted,
                "Signature": base64.b64encode(digester.digest()),
            },
            json=body,
            verify=False,
        )

    def get_version(self) -> APIVersion:
        response = self._request("GET", "/api/version")
        payload = response.json()

        return APIVersion(api_version=payload["api_version"], server_version=payload["server_version"])

    def get_domains(self):
        response = self._request("GET", "/api/v1/availabledomains")
        payload = response.json()

        domains = list()
        for domain in payload:
            domains.append(Domain(domain["name"], domain["id"], domain["collected"]))

        return domains

    def get_description(self,ap):
        return requests.request(
            method="GET",
            url=self._format_url("/ui/findings/{}/short_description.md".format(ap)),
            headers={
                "User-Agent": "bhe-python-sdk 0001",
            },
            verify=False,
        ).content

    def get_remediation(self,ap):
        return requests.request(
            method="GET",
            url=self._format_url("/ui/findings/{}/short_remediation.md".format(ap)),
            headers={
                "User-Agent": "bhe-python-sdk 0001",
            },
            verify=False,
        ).content



'''
CMDs
'''

def test_module(client):
    version = client.get_version()
    if version:
        demisto.results('ok')
        sys.exit(0)


def run_api(client,method, uri):
    resp = client._request(method,uri)
    return resp.content

def lookup_user(client,user):
    try:
        ret = json.loads(run_api(client,"GET","/api/v1/search?q={}".format(user)))
    except:
        demisto.results("Error finding user {}".format(user))
        sys.exit(-1)
    sid=None
    try:
        for u in ret:
            if u['name'].lower().startswith(user.lower()) and "@" in u['name']:
                sid = u['objectid']
    except:
        demisto.results("Error parsing API search")
        sys.exit(-1)

    if sid:
        try:
            ret = json.loads(run_api(client,"GET","/api/v1/entities/users/{}".format(sid)))
        except:
            demisto.results("Error doing lookup for user {}, sid {}. Are you sure it is a user?".format(user,sid))
            sys.exit(-1)
    else:
        demisto.results("No user found")
        sys.exit(0)
    #do time translates
    fixups = ("lastlogon", "lastlogontimestamp", "pwdlastset", "whencreated")
    for f in fixups:
        try:
            ret['props'][f] = datetime.fromtimestamp(ret['props'][f]).ctime()
        except:
            pass
    return ret

def lookup_host(client,host):
    try:
        ret = json.loads(run_api(client,"GET","/api/v1/search?q={}".format(host)))
    except:
        demisto.results("Error finding host, {}".format(host))
        sys.exit(-1)
    sid=None
    for u in ret:
        if u['name'].lower().startswith(host.lower()) and ".dom1" in u['name'].lower() :
            sid = u['objectid']
    if sid:
        try:
            ret = json.loads(run_api(client,"GET","/api/v1/entities/computers/{}".format(sid)))
        except:
            demisto.results("Error doing lookup for host {}, sid {}. Are you sure it is a host?".format(host,sid))
            sys.exit(-1)
    else:
        demisto.results("No host found")
        sys.exit(0)
    #do time translates
    fixups = ("lastlogon", "lastlogontimestamp", "pwdlastset", "whencreated")
    for f in fixups:
        try:
            ret['props'][f] = datetime.fromtimestamp(ret['props'][f]).ctime()
        except:
            pass
    return ret

def lookup_group(client,group):
    if " " in group:
        group = group.replace(" ","%20")
    ret = json.loads(run_api(client,"GET","/api/v1/search?q={}".format(group)))
    sid=None
    for u in ret:
        if u['name'].lower().startswith(group.lower().replace("%20"," ")):
            sid = u['objectid']
    if sid:
        ret = json.loads(run_api(client,"GET","/api/v1/entities/groups/{}".format(sid)))
    else:
        demisto.results("No group found")
        sys.exit(0)
    return ret

def enum_prop(client,typ,name,prop):
    if typ == "users":
        o = lookup_user(client,name)
    elif typ == "computers":
        o = lookup_host(client,name)
    elif typ == "groups":
        o = lookup_group(client,name)
    else:
        return "Error, not valid object type for session enumeration"
    try:
        sid = o['props']['objectid']
    except:
        return "{} does not exist in AD".format(name)

    sessions = run_api(client,"GET","/api/v1/entities/{}/{}/{}?limit=100".format(typ,sid,prop))
    return

def safe_get(d, *keys):
    """Safely get a value from a nested dictionary."""
    for key in keys:
        try:
            d = d[key]
        except (KeyError, TypeError):
            return None
    return d

def refine_attack_path_list(aps,ap_type):
    refined_aps = []
    # Update this list over time to include Attack Path types where there is a From and To Principle
    if ap_type in ("T0Logins","LargeDefaultGroupsDCOM","UnconstrainedRDP","T0RDP","LargeDefaultGroupsGenericWrite","LargeDefaultGroupsAdmins","T0Admins","NonT0DCSyncers","LargeDefaultGroupsRDP","T0WriteOwner","T0GenericAll","T0GenericWrite","T0WriteDACL","T0AllExtendedRights","T0Owns"):
        for ap in aps['data']:
            try:
                from_dn = ap['FromPrincipalProps']['distinguishedname']
            except:
                from_dn = None
            try:
                if not from_dn and ap_type == "NonT0DCSyncers" and "(PLACEHOLDER_DOMAIN1)" in ap['FromPrincipalProps']['name'] :
                    from_dn = "(TEST.EDU)"
            except:
                from_dn = None
            try:
                from_name = ap['FromPrincipalProps']['name']
            except:
                from_name = None
            try:
                from_tags = ap['FromPrincipalProps']['system_tags']
            except:
                from_tags = None
            try:
                to_dn = ap['ToPrincipalProps']['distinguishedname']
            except:
                to_dn = None
            try:
                to_name = ap['ToPrincipalProps']['name']
            except:
                to_name = None
            try:
                to_tags = ap['ToPrincipalProps']['system_tags']
            except:
                to_tags = None
            try:
                created = ap['created_at']
            except:
                created = None
            try:
                updated = ap['updated_at']
            except:
                updated = None
            try:
                if ap['Accepted']:
                    muted = "True"
                else:
                    muted = "False"
            except:
                muted = "Unknown"
            #muted="test"
            refined_aps.append({"from_dn":from_dn,"from_name":from_name,"from_tags":from_tags,"to_dn":to_dn,"to_name":to_name,"to_tags":to_tags,"created":created,"updated":updated,"muted":muted})
    # Update this list over time to include Attack Path types where there is not a From and To Principle
    elif ap_type in ("Kerberoasting","T0MarkSensitive"):
        for ap in aps['data']:
            try:
                desc = ap['Props']['description']
            except:
                desc = None
            try:
                name = ap['Props']['name']
            except:
                name = None
            try:
                dn = ap['Props']['distinguishedname']
            except:
                dn = None
            try:
                last_seen = ap['Props']['lastseen']
            except:
                last_seen = None
            try:
                admin_rights_count = ap['Props']['admin_rights_count']
            except:
                admin_rights_count = None
            try:
                created = ap['created_at']
            except:
                created = None
            try:
                updated = ap['updated_at']
            except:
                updated = None
            try:
                if ap['Accepted']:
                    muted = "True"
                else:
                    muted = "False"
            except:
                muted = "Unknown"
            refined_aps.append({"desc":desc,"name":name,"dn":dn,"last_seen":last_seen,"admin_rights_count":admin_rights_count,"created":created,"updated":updated,"muted":muted})
    else:
        demisto.results("Error, unknown attack type \"{}\". Please notify admin to add handling for it.".format(ap_type))
        sys.exit(-1)
    return refined_aps

def get_attack_paths(client, ap_type, domain,debug):
    if not ap_type:
        at = run_api(client,"GET","/api/v1/risks/{}/availabletypes".format(domain_sid))
        return at
    else:
        ap = json.loads(run_api(client,"GET","/api/v1/risks/{}/details?finding={}&limit=100".format(domain_sid,ap_type)))
        if debug == "Yes":
            return ap
        refined_ap = refine_attack_path_list(ap,ap_type)
        return refined_ap

def run_pathfinding(client, o1, o1_type, o2, o2_type) -> (str, bool):
    o1_sid = None
    o2_sid = None
    if o1_type.lower() == "user":
        o1_sid = lookup_user(client,o1)["props"]['objectid']
    elif o1_type.lower() == "host":
        o1_sid = lookup_host(client,o1)["props"]['objectid']
    else:
        return "o1_type was not user or host", False

    if o2_type.lower() == "user":
        o2_sid = lookup_user(client,o2)["props"]['objectid']
    elif o2_type.lower() == "host":
        o2_sid = lookup_host(client,o2)["props"]['objectid']
    else:
        return "o2_type was not user or host", False

    if o1_sid and o2_sid:
        try:
            ret = json.loads(run_api(client,"GET","/api/v1/graph/pathfinding?start_node={}&end_node={}".format(o1_sid,o2_sid)))
            return ret, bool(len(ret) > 0)
        except:
            ret = "Error getting path for {} and {}".format(o1, o2)
            return ret, False
    else:
        return "No attack path found", False

def trim_path(path,start,end):
    nodes = {}
    edges = {}
    out = []
    for o in path:
        try:
            nodes[o] = path[o]['data']['name']
        except:
            pass
        if o.startswith('rel'):
            try:
                edges[o] = {"label":path[o]['label']['text'],"From":path[o]['id1'],"To":path[o]['id2']}
            except Exception as e:
                pass
    last = ""
    for i in range(len(edges)):
        for e in edges:
            if i == 0 and nodes[edges[e]['From']] == start:
                out.append("{} ---{}---> {}".format(nodes[edges[e]['From']],edges[e]['label'],nodes[edges[e]['To']]))
                last = nodes[edges[e]['To']]
            elif  i == len(edges) and nodes[edges[e]['To']] == end:
                out.append("{} ---{}---> {}".format(nodes[edges[e]['From']],edges[e]['label'],nodes[edges[e]['To']]))
            elif last == nodes[edges[e]['From']]:
                out.append("{} ---{}---> {}".format(nodes[edges[e]['From']],edges[e]['label'],nodes[edges[e]['To']]))
                last = nodes[edges[e]['To']]
    if len(out) == 0:
        out = "No Path exists"
    return out

def get_attack_path_info(client,ap,info):
    ec = {}
    if info == "Description":
        ret = client.get_description(ap)
        ec = {"ap_description":ret.decode('UTF-8')}
    elif info == "Remediation":
        ret = client.get_remediation(ap)
        ec = {"ap_remediation":ret.decode('UTF-8')}
    else:
        return None


    return ret, ec


def enum_pathfinding(client, o1, o1_type):
    # get id
    if o1_type.lower() == "user":
        o1_sid = lookup_user(client,o1)["props"]['objectid']
    elif o1_type.lower() == "host":
        o1_sid = lookup_host(client,o1)["props"]['objectid']
    else:
        return "o1_type was not user or host", False
    # check these attack types; list can be adjusted later
    attack_types = ["LargeDefaultGroupsWriteAccountRestrictions","T0Logins","T0WriteAccountRestrictions","T0MarkSensitive","Kerberoasting"]
    msg = ""
    domain_sid = "[PUT YOUR DOMAIN SID HERE]"
    table = {"data": []}
    for ap_type in attack_types:
        # get all nodes in attack path
        ap = json.loads(run_api(client,"GET","/api/v1/risks/{}/details?finding={}&limit=100".format(domain_sid,ap_type)))
        if "data" not in ap:
            continue
        # otherwise check each node until one has a path with the src
        row = { "aptype":ap_type, "id": "", "name":"", "dname": "", "spname": "" }
        for node_data in ap.get("data", []):
            # node fields of interest
            if ap_type in ["T0MarkSensitive", "Kerberoasting"]:
                o2_sid = node_data["Principal"]
                o2_name = node_data["Props"]["name"]
                o2_dname = node_data["Props"]["distinguishedname"]
                o2_spname = ",".join(node_data["Props"]["serviceprincipalnames"])
            else:
                o2_sid = node_data["ToPrincipal"]
                o2_name = node_data["ToPrincipalProps"]["name"]
                o2_dname = node_data["ToPrincipalProps"]["distinguishedname"]
                o2_spname = ",".join(node_data["ToPrincipalProps"]["serviceprincipalnames"])
            # run pathfinding from src to node
            ret = json.loads(run_api(client,"GET","/api/v1/graph/pathfinding?start_node={}&end_node={}".format(o1_sid,o2_sid)))
            if ret:
                row["id"] = o2_sid
                row["name"] = o2_name
                row["dname"] = o2_dname
                row["spname"] = o2_spname
                break
        table["data"].append(row)
    return table

'''
MAIN FUNCTION
'''

def main() -> None:
    bh_url = demisto.params().get('bloodhound_url').strip()
    bh_token_id = demisto.params().get('token_id').strip()
    bh_token_key = demisto.params().get('token_key').strip()

    credentials = Credentials(
        token_id=bh_token_id,
        token_key=bh_token_key,
    )

    # Create the client and perform an example call using token request signing
    client = Client(scheme="https", host=bh_url, port=443, credentials=credentials)

    if demisto.command() == "test-module":
        test_module(client)
    elif demisto.command() == "bh-lookup-user":
        u = lookup_user(client,demisto.args()["Name"])
        demisto.results(u)
    elif demisto.command() == "bh-lookup-host":
        h = lookup_host(client,demisto.args()["Host"])
        demisto.results(h)
    elif demisto.command() == "bh-lookup-group":
        g = lookup_group(client,demisto.args()["Group"])
        demisto.results(g)
    elif demisto.command() == "bh-enum-sessions":
        s = enum_prop(client,demisto.args()["Type"],demisto.args()["Name"],"sessions")
        demisto.results(s)
    elif demisto.command() == "bh-enum-admin-rights":
        ar = enum_prop(client,demisto.args()["Type"],demisto.args()["Name"],"adminrights")
        demisto.results(ar)
    elif demisto.command() == "bh-get-attack-paths":
        try:
            debug = demisto.args()['debug']
        except:
            debug = "No"
        try:
            ap_type = demisto.args()['AP_Type']
        except:
            demisto.results("Error - No AP_Type provided")
            sys.exit(-1)
        ap = get_attack_paths(client,ap_type,demisto.args()["domain"],debug)
        if debug == "No":
            demisto.results({'ContentsFormat':formats['table'],"Type":entryTypes['note'],'Contents':ap})
        elif debug == "Yes":
            demisto.results(ap)

    elif demisto.command() == "bh-list-attack-path-types":
        ap = get_attack_paths(client,None,demisto.args()["domain"],"No")
        demisto.results(ap)
    elif demisto.command() == "bh-pathfinding":
        path, exists = run_pathfinding(client,demisto.args()["src"],demisto.args()["src_type"],demisto.args()["dst"],demisto.args()["dst_type"])
        path_text = ("\n".join(trim_path(path,demisto.args()["src"],demisto.args()["dst"])))
        return_results({
            "Contents": path_text,
            "ContentsFormat": formats["text"],
            "EntryContext": {
                "bhe.path_exists": exists,
            },
        })
    elif demisto.command() == "bh-get-attack-path-info":
        ret, ec = get_attack_path_info(client,demisto.args()['attack_path'],demisto.args()['info'])
        command_results: List[CommandResults] = []
        command_results.append(
            CommandResults(
                       outputs_prefix='bhe',
                       outputs=ec,
            )
        )
        return_results(command_results)
    elif demisto.command() == "bh-pathfinding-attack-paths":
        g = enum_pathfinding(client,demisto.args()["src"],demisto.args()["src_type"])
        demisto.results(g)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()

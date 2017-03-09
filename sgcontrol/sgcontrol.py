#!/usr/bin/env python

# sgcontrol - AWS Security Group Manager
# by Noah Masur


###--- Setup ---###

# Required packages
import ec2, boto

# Standard library
import sys, os, argparse, yaml, ConfigParser

# Globals
DEFAULT_FILENAME = "sg_list.yml"
DEV_ENV_PREFIX = "DEV_"
DEV_FILE_PREFIX = "dev_"

# Python 3 considerations
try:
    input = raw_input
except NameError:
    pass

# API Environment Credentials
# Export these vars to your bash to prevent EC2, etc. prompting
env = { 
        'AWS_ACCESS_KEY_ID'     : None,
        'AWS_SECRET_ACCESS_KEY' : None,
        'AWS_REGION'            : None,
        'SG_RULES_FILE'         : None,
      }

# Colors
class col:
    PURPLE    = '\033[95m'
    BLUE      = '\033[94m'
    GREEN     = '\033[92m'
    ORANGE    = '\033[93m'
    RED       = '\033[91m'
    ENDC      = '\033[0m'
    BOLD      = '\033[1m'
    UNDERLINE = '\033[4m'

# Colored versions of string statements
def cstr(text, color):
    return (color + text + col.ENDC)

def cprint(text, color):
    print(cstr(text, color))

def error(text):
    sys.stderr.write(cstr(text, col.RED) + '\n')

# SecurityGroup Data Class
class SecurityGroup:
    def __init__(self, **entries):
        self.__dict__.update(entries)

    def __str__(self):
        return self.name + " (Security Group)"

# SGRuleset Data Class
class SGRuleset:
    def __init__(self, **entries):
        self.__dict__.update(entries)

    def __str__(self):
        return self.ports + ": " + self.cidr_ips

# Group ID Data Class
class SGId:
    @staticmethod
    def cleanId(text):
        if len(text.split('-')) == 3:
            return '-'.join(text.split('-')[0:2])
        else:
            return text

    def __init__(self, group_id, group_obj):
        self.group_id = SGId.cleanId(group_id)
        self.owner_id = group_obj.owner_id

    def __str__(self):
        return "SGId: " + '-'.join([group_id, owner_id])

###--- Local Processing Actions ---###

# Command line argument parsing
def parseArguments():
    parser = argparse.ArgumentParser(description='Apply security group rules to EC2.')
    parser.add_argument('-f', '--force', action='store_true', help='apply changes to sg rules')
    parser.add_argument('-k', '--key', action='store_false', help='interactive key prompts')
    parser.add_argument('-d', '--dump', action='store_true', help='dump live rules to local file')
    parser.add_argument('-e', '--dev', action='store_true', help='use separate dev information')
    parser.add_argument('-p', '--profile', default='')
    parser.add_argument('-S', '--secret', default='')
    parser.add_argument('-A', '--access', default='')
    parser.add_argument('-R', '--region', default='')
    parser.add_argument('rules', nargs='?', type=str, help='input YAML file with rules')

    options = parser.parse_args(sys.argv[1:])
    return options

# Get basic credential information from user
def getCredentials(options):
    # Use -k to turn off env variable check
    if options.key:

        # Check AWS config file path
        try:
            credentialpath = os.path.expanduser('~/.aws/credentials')
            configpath = os.path.expanduser('~/.aws/config')
            cp = ConfigParser.ConfigParser()
            if os.path.isfile(credentialpath):
                cp.readfp(open(credentialpath))
                if cp.sections():
                    section = cp.sections()[0]
                    if options.profile:
                        section = cp.sections()[cp.sections().index(options.profile)] 
                    env['AWS_ACCESS_KEY_ID'] = cp.get(section, 'aws_access_key_id')
                    env['AWS_SECRET_ACCESS_KEY'] = cp.get(section, 'aws_secret_access_key')

            if os.path.isfile(configpath):
                cp.readfp(open(configpath))
                if cp.sections():
                    if options.profile:
                        section = cp.sections()[cp.sections().index(options.profile)] 
                    env['AWS_REGION'] = cp.get(section, 'region')
        except ValueError:
            error("Profile \"{}\" not found in AWS config files.".format(options.profile))
            sys.exit(1)

        # Check shell env variables and override config file
        for e in env:
            try:
                if options.dev:
                    env[e] = os.environ[DEV_ENV_PREFIX + e]
                else:
                    env[e] = os.environ[e] 
            except KeyError:
                pass

    # Or override env vars with -A, -S, -R flags
    try:
        ec2.credentials.ACCESS_KEY_ID = (
            options.access or 
            env['AWS_ACCESS_KEY_ID'] or
            input("AWS Access Key: ")
        )
        ec2.credentials.SECRET_ACCESS_KEY = (
            options.secret or 
            env['AWS_SECRET_ACCESS_KEY'] or
            input("AWS Secret Key: ")
        )
        ec2.credentials.REGION_NAME = (
            options.region or 
            env['AWS_REGION'] or
            input("AWS Region: ")
        )
    except KeyboardInterrupt:
        print("\n\nInterrupt detected. Exiting.\n")
        sys.exit(0)

# Hack to build dump file
def dump():
    all_sgs = ec2.security_groups.all() 
    dumpdata = []
    for sg in all_sgs:
        if sg.name == 'default':
            continue
        group = {}
        group['name'] = sg.name
        group['rulesets'] = []
        for rule in sg.rules:
            ruleset = {}
            ruleset['ports'] = [int(rule.to_port)]
            ruleset['cidr_ips'] = []
            for grant in rule.grants:
                cidr_ip = ""
                if grant.group_id:
                    cidr_ip = grant.group_id
                else:
                    cidr_ip = grant.cidr_ip
                ruleset['cidr_ips'].append(cidr_ip)
            # Merge multiple ports for the same rules (all must match)
            ruleset_added = False
            for local_ruleset in group['rulesets']:
                if not ruleset_added:
                    local_ip_set = set(local_ruleset['cidr_ips'])
                    live_ip_set = set(ruleset['cidr_ips'])
                    if not local_ip_set.difference(live_ip_set):
                        local_ruleset['ports'].extend(ruleset['ports'])
                        ruleset_added = True
            # Otherwise just add the whole set for the port
            if not ruleset_added:
                group['rulesets'].append(ruleset)

        if group['rulesets']:
            dumpdata.append(group)

    print (yaml.safe_dump(dumpdata, default_flow_style=False))

# Use default file if none provided
def chooseReadFile(options):
    filename = DEFAULT_FILENAME 
    if options.dev:
       filename = DEV_FILE_PREFIX + filename
    filename = options.rules or env['SG_RULES_FILE'] or filename
    filepath = os.path.abspath(filename)
    if not os.path.isfile(filepath):
        try:
            filepath = os.path.abspath(input("SG ruleset YAML file: "))
            print("")
        except KeyboardInterrupt:
            print("\n\nInterrupt detected. Exiting.\n")
            sys.exit(0)
    cprint("Using YAML file: {}\n".format(filepath), col.BLUE)
    return filepath

# Collect security group rule list from file
def getLocalGroups(filepath):
    security_groups = []
    try:
        with open(filepath, 'r') as stream:
            sg_dicts = yaml.load(stream)
            for sg_dict in sg_dicts:
                rulesets = sg_dict['rulesets']
                for i in range(len(rulesets)):
                    rulesets[i] = SGRuleset(**rulesets[i])
                security_groups.append(SecurityGroup(**sg_dict))
    except IOError:
        error("No file found named {}.".format(filepath))
        sys.exit(1)
    except yaml.YAMLError:
        error("Invalid YAML formatting.")
        sys.exit(1)
    return security_groups

###--- AWS Actions ---###

# Get AWS Security Group object
def getLiveGroup(sg):
    try:
        group = ec2.security_groups.get(name=sg.name)
    except ec2.security_groups.DoesNotExist:
        error('Security group not found: {}'.format(sg.name))
        sys.exit(1)
    except boto.exception.EC2ResponseError as e:
        if '401 Unauthorized' in str(e):
            error('Unauthorized access key.')
        else:
            error(str(e))
        sys.exit(1)
    except AttributeError:
        error('Could not connect to AWS region \'{}\'.'.format(
                ec2.credentials.REGION_NAME))
        sys.exit(1)
    return group

# Collect live rules
def getLiveRules(group):
    live_rules = set() 
    for rule in group.rules:
        port = int(rule.from_port)
        for grant in rule.grants:
            cidr_ip = SGId.cleanId(str(grant))
            live_rules.add((port, cidr_ip))
    return live_rules

# Collect local rules
def getLocalRules(sg):
    local_rules = set()
    for ruleset in sg.rulesets: 
        for port in ruleset.ports:
            for cidr_ip in ruleset.cidr_ips:
                cidr_ip = SGId.cleanId(cidr_ip)
                local_rules.add((port, cidr_ip))
    return local_rules

# Compare differences
def compareRules(group, live_rules, local_rules, options):
    to_be_revoked = live_rules.difference(local_rules)
    to_be_authorized = local_rules.difference(live_rules)

    def describeChange(differences, message):
        print (message)
        for (port, cidr_ip) in differences:
            print ('        * {} - TCP, {}, {}'.format(group.name, port, cidr_ip))
        print ("")

    if not options.force and (to_be_revoked or to_be_authorized):
        cprint ('{}:\n'.format(group.name), col.PURPLE)

        if to_be_revoked:
            describeChange(to_be_revoked, cstr("    To be revoked:", col.RED))

        if to_be_authorized:
            describeChange(to_be_authorized, cstr("    To be authorized:", col.GREEN))

    return (to_be_revoked, to_be_authorized)

# Apply differences
def applyChanges(group, to_be_revoked, to_be_authorized):
    cprint ("Applying security groups on {}...\n".format(group.name), col.ORANGE)
    current_ip = ""
    try:
        difflists = [
            {'list': to_be_revoked, 'action': group.revoke, 'header': 'Revoked:', 
                'color': col.RED},
            {'list': to_be_authorized, 'action': group.authorize, 'header': 'Authorized:',
                'color': col.GREEN}
        ]
        for difflist in difflists:
            for (port, cidr_ip) in difflist['list']:
                current_ip = cidr_ip
                if not cidr_ip[0].isdigit():
                    difflist['action']('tcp', port, port, src_group=SGId(cidr_ip, group))
                else:
                    difflist['action']('tcp', port, port, cidr_ip=cidr_ip)
                print ('        * {} {} - TCP, {}, {}'.format(
                        cstr(difflist['header'], difflist['color']), group.name, port, cidr_ip
                    ))

    except boto.exception.EC2ResponseError as e:
        if '403 Forbidden' in str(e):
            error('Forbidden to make changes to the security group "{}".'.format(group.name))
        elif '400 Bad Request' in str(e):
            if 'maximum number of rules' in str(e):
                error('Too many rules in your security group "{}".'.format(group.name))
            else:
                error('Improper values or formatting given: {}.'.format(current_ip))
        else:
            error(str(e))
        sys.exit(1)
    print ("\n      Done.\n")

# Print final response
def summarize(options, has_diffs):
    if options.force:
        if has_diffs:
            print ("All changes applied.\n")
        else: 
            print ("No changes to apply.\n")
    else:
        if has_diffs:
            print ("Use -f to apply changes.\n")
        else:
            print ("No differences found.\n")

###--- Program Execution ---###
def main():
    options = parseArguments()
    getCredentials(options)
    # Dump live to local
    if options.dump:
        dump()
    # Compare local to live
    else:
        filepath = chooseReadFile(options)
        security_groups = getLocalGroups(filepath)
        has_diffs = False
        for sg in security_groups:
            group = getLiveGroup(sg)
            live_rules = getLiveRules(group)
            local_rules = getLocalRules(sg) 
            (revoke, authorize) = compareRules(group, live_rules, local_rules, options)
            has_diffs = bool(revoke or authorize or has_diffs)
            # Make changes to live
            if options.force and (revoke or authorize):
                applyChanges(group, revoke, authorize)
        summarize(options, has_diffs)

if __name__ == "__main__":
    main()


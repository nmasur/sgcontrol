# sgcontrol
Fool-proof AWS security group management.

Written by Noah Masur for Take-Two Interactive. Inspired by [sgmanager](https://github.com/gooddata/sgmanager), but also works with VPC security group IDs, and allows you to write one list of IPs for several ports.

## Using sgcontrol
Dump current AWS security groups to file:

```python sgcontrol.py -d > sg_list.yml```

Compare local file to current AWS security groups:

```python sgcontrol.py sg_list.yml```

Apply local changes to current AWS security groups:

```python sgcontrol.py -f sg_list.yml```

## AWS Credentials
sgcontrol checks for AWS IAM credentials in the following priority:

1. If using flags -A, -S, -R
2. Environment vars AWS_ACCESS_KEY, AWS_SECRET_KEY, AWS_REGION
3. Interactive prompts

Make sure your AWS IAM role or user has access to your security groups

## Other flags
- `-f` or `--force` applies changes to AWS
- `-d` or `--dump` writes AWS groups in YAML format to stdout (or file)
- `-k` or `--key` forces interactive prompt for AWS credentials
- `-e` or `--dev` adds the `DEV_` prefix to environment vars, and `dev_` to default file name

## YAML File Format
You can get your current security groups dumped in format by running `-d`, but here is the way to format the YAML file from scratch:

```
---
- name: SG Group Name
  rulesets:
    - ports:
        - 80
        - 443
      cidr_ips:
        - 99.99.99.99/32
        - 199.199.199.199/32
        - 299.299.299.299/32
    - ports:
        - 22
      cidr_ips:
        - 99.99.99.99/32
        - sg-99999921

# This group controls the database
- name: SG Other Group
  rulesets:
    - ports:
        - 3306
    - cidr_ips:
        - 99.99.99.99/32
        - 1.2.3.4/32
```

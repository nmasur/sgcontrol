# sgcontrol
Fool-proof AWS security group management.

Written by Noah Masur for Take-Two Interactive.

Inspired by sgmanager, but works on VPC security group IDs.

## Using sgcontrol
Dump current AWS security groups to file:

```python sgcontrol -d > sg_list.yml```

Compare local file to current AWS security groups:

```python sgcontrol sg_list.yml```

Apply local changes to current AWS security groups:

```python sgcontrol -f sg_list.yml```

## YAML File Format
You can get your current security groups dumped in format by running `-d`, but here is the way to format the YAML file from scratch:

```---
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
        - 1.2.3.4/32```

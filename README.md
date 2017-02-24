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

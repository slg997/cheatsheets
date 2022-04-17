# Ref link: https://yara.readthedocs.io/en/stable/writingrules.html

# The following is a list of data points useful for writing a yara rule:

- Hardcoded file paths (Not installation names)
- Unusual API calls that the files reference
- Function names
- Registry keys
- Unsual string format

# Use regular expression to match (slower):

rule example1

{
   strings:
       $re1 = /md5: [0-9a-ZA-Z]{32}/
       $re2 = /state: (on|off)/
   condition:
       $re1 and $re2
}

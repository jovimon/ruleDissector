ruleDissector
=============
Authors:
 @jovimon
 @j0sm1
 
Python script to parse a Snort config directory and load the active ruleset to memory.

Then you can use the variable to search within the ruleset or modify any rule.

Usage: 

Import the script to your code and call it (all parameters are optional, default values shown here):

ruleset = rulesetParser(basedir = ‘/usr/local/snort/etc’, snortfile = 'snort.conf', classiffile = 'classification.config', rulesdir = 'rules')

Examples: 

To get message from all rules related to Palevo botnet:

for regla in ruleset.ruleset:
    if regla.getMsg().find(‘Palevo’) != -1:
        print regla.getMsg()

To get all rules with priority = 2:

contador = 0
for regla in ruleset.ruleset:
    if regla.getArgument(‘priority’) == ‘2’:
        contador++
print contador

Limitations:

Detection of modifiers of content parameters not fully implemented. For example, a rule with this content:
content:"|03|"; offset: 0; depth: 1;
Will generate 3 arguments: name “content” and value “|03|”, name “offset” and value 0, and, finally, name “depth” and value 1.
The only exception are parameters without value (e.g. nocase). For example, a rule with this content:
content:".php"; nocase;
Will generate a single argument, with name “content” and value ‘ “.php”; nocase’.

Functions getArgument and setArgument are not prepared to work with 2+ parameters with same name, and will always show the first parameter.


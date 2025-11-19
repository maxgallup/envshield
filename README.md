# envshield
Define a schema that includes which environment variables need to be defined in the .env file.





* make references to variables in the schema's namespace that have the following syntax:

```
[MY_OG_VAR]
description = "something"

[MY_OG_VAR_2]
description = "something"

[MY_DEPENDENT_VAR]
description = "{{ MY_OG_VAR_2 }} something"
default = "{{ MY_DEPENDENT_VAR }} something"

[OPTIONAL]
description = "asdf"
optional = true


[DEFAULT]
description = "asdf"
default = "some_val"

[SECRET]
description = "some secret"

```

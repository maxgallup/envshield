# envshield
`envshield` is a simple tool that enforces variables in an environment according to schema.

## Quick Start

```bash
# Install
cargo install envshield
# Run the command in the same directory as the schema file: env.toml
envshield
```

The schema defines the expected environment variables that your project depends on. It allows
you to specify whether environment variables are optional, have default values or even expected
concrete values. Based on the schema, it reports what environment variables are present and
whether any of them deviate from expected values. Take the following schema for example:

```toml
# Version must be set to "1"
version = "1"

# Here we define an environment variable with an expected value and (are required to) provide
# a description. This helps to self document the environment variables in a complex project.
[DOMAIN]
value = "https://example.com"
description = "The domain used by the application."
# Suggests that an environment variable must be present and provides a default for the user
# to use.
[LOG_LEVEL]
default = "warn"
description = "Which logging level the program uses [debug, warn or error]"

# With just a description it enforces that an environment variable is present, but doesn't
# enforce a value. Useful for secrets.
[API_KEY]
description = "Authentication key used only during local testing."

# Truly optional variables will not be enforced.
[RUST_BACKTRACE]
optional = true
description = "When set to 1, captures stack backtrace of an OS Thread"

# Values from other variables can be referenced using `{{ KEY }}` syntax.
[DATABASE_URL]
value = "{{ DOMAIN }}/api/database"
description = "Database URL used by the PG database."
```

When running `envshield` in an environment that has none of the variables above set we
get the following output:

```text
$ envshield
Parsed:   schema at: ./env.toml
Warning:  1 optional variables missing from env:
          RUST_BACKTRACE
Error:    4 required variables missing from env:
(value)   DOMAIN        : 'https://example.com'
(value)   DATABASE_URL  : 'https://example.com/api/database'
(default) LOG_LEVEL     : 'warn'
(secret)  API_KEY
```

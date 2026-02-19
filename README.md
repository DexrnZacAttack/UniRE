# UniRE
Simple universal interfaces that work on both IDA and Ghidra

> [!NOTE]
> I'm not all that experienced in Python, so the code quality may be subpar.

## Usage
```py
# init logging
use_default_logging_config()

# get the tool instance
re_tool: IReTool = ReToolFactory.get_re_tool()

# you may use it from here
```
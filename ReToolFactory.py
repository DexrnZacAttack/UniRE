import UniRE
from UniRE.interfaces.IReTool import IReTool


class ReToolFactory:
    def get_re_tool() -> IReTool:
        tool = None

        if tool is None:
            try:
                from UniRE.impls.ModernIDAReTool import ModernIDAReTool

                tool = ModernIDAReTool()
            except ImportError:
                pass

        if tool is None:
            try:
                from UniRE.impls.IDAReTool import (
                    IDAReTool,
                )  # if this fails, then it means we aren't using IDA, because the IDA imports don't work

                tool = IDAReTool()
            except ImportError:
                pass

        if tool is None:
            try:
                from UniRE.impls.GhidraReTool import GhidraReTool

                tool = GhidraReTool()
            except ImportError:
                pass

        if tool is None:
            raise RuntimeError("Bad environment? Can't get an instance of ReTool!!!")

        tool._logger.info(
            f"Initialized ReTool with environment {tool.environment_type.name}"
        )

        return tool

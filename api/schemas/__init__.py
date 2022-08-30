from pydantic import BaseModel, Extra


BaseModel.Config.extra = Extra.forbid

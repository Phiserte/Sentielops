from pydantic import BaseModel, ConfigDict, Field, HttpUrl, StringConstraints
from typing import Annotated


NonEmpty = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
CommitSha = Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]{7,64}$")]


class CLIPushRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repository_name: NonEmpty
    repository_full_name: Annotated[str, StringConstraints(pattern=r"^[^/]+/[^/]+$")]
    clone_url: HttpUrl
    default_branch: NonEmpty
    branch: NonEmpty
    before_commit: CommitSha
    after_commit: CommitSha
    sender: NonEmpty

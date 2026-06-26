# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from typing import Any

def __getattr__(name: str) -> Any: ...

# Placeholder stub.
class QuerySet:
    def extra(
        self,
        select: Optional[Dict[str, str]] = None,
        where: Optional[List[str]] = None,
        params: Optional[List[Any]] = None,
        tables: Optional[List[str]] = None,
        order_by: Optional[List[str]] = None,
        select_params: Optional[List[Any]] = None,
    ) -> QuerySet: ...
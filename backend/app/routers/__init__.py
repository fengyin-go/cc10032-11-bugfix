"""业务路由汇总：所有模块共用一套资源路由，由领域服务完成分派。"""
from __future__ import annotations

from app.routers import cep_alert, resource

# 固定路径路由（CEP 台账 / 恢复核对）必须先于通用资源路由注册。
ROUTERS = [cep_alert, resource]

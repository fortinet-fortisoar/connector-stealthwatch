""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
from .operation import operations, check_health
from connectors.core.connector import Connector, get_logger, ConnectorError

logger = get_logger('stealthwatch')


class Stealthwatch(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            operation = operations.get(operation, None)
            result = operation(config, params, **kwargs)
            return result
        except Exception as err:
            logger.exception("An exception occurred [{}]".format(err))
            raise ConnectorError("An exception occurred [{}]".format(err))

    def check_health(self, config):
        try:
            return check_health(config)
        except Exception as err:
            logger.exception("An exception occurred [{}]".format(err))
            raise ConnectorError("An exception occurred [{}]".format(err))

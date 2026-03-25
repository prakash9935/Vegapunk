from vegapunk.ingestion.parsers.splunk import SplunkParser
from vegapunk.ingestion.parsers.elastic import ElasticParser
from vegapunk.ingestion.parsers.wazuh import WazuhParser

PARSER_REGISTRY = {
    "splunk": SplunkParser,
    "elastic": ElasticParser,
    "wazuh": WazuhParser,
}

__all__ = ["SplunkParser", "ElasticParser", "WazuhParser", "PARSER_REGISTRY"]

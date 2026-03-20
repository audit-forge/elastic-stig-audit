from .auth_checks import ElasticsearchAuthChecker
from .encryption_checks import ElasticsearchEncryptionChecker
from .network_checks import ElasticsearchNetworkChecker
from .authz_checks import ElasticsearchAuthzChecker
from .logging_checks import ElasticsearchLoggingChecker
from .cluster_checks import ElasticsearchClusterChecker
from .container_checks import ElasticsearchContainerChecker

ALL_CHECKERS = [
    ElasticsearchAuthChecker,
    ElasticsearchEncryptionChecker,
    ElasticsearchNetworkChecker,
    ElasticsearchAuthzChecker,
    ElasticsearchLoggingChecker,
    ElasticsearchClusterChecker,
    ElasticsearchContainerChecker,
]

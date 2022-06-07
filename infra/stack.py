from unicodedata import name
from urllib.parse import uses_relative
from aws_cdk import (
    RemovalPolicy,
    Stack,
    aws_cognito as cognito,
    aws_secretsmanager as secretsmanager,
    CfnOutput,
    custom_resources as cr,
)
from constructs import Construct


class InfraStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        userpool = self.create_userpool()
        programmatic_client = self.add_programmatic_client(userpool)
        service_client = self.add_service_client(userpool)

    def create_userpool(self) -> cognito.UserPool:
        userpool = cognito.UserPool(
            self,
            "userpool",
            user_pool_name="alukach-example",
            removal_policy=RemovalPolicy.DESTROY,
            self_sign_up_enabled=False,
            sign_in_aliases={"username": True, "email": True},
            sign_in_case_sensitive=False,
            standard_attributes=cognito.StandardAttributes(
                email=cognito.StandardAttribute(required=True)
            ),
        )

        userpool.add_domain(
            "cognito-domain",
            cognito_domain=cognito.CognitoDomainOptions(
                domain_prefix="auth-playground"
            ),
        )

        return userpool

    def add_programmatic_client(
        self, userpool: cognito.UserPool
    ) -> cognito.UserPoolClient:
        client = userpool.add_client(
            "api-access",
            auth_flows=cognito.AuthFlow(user_password=True),
            generate_secret=False,
            user_pool_client_name="Programmatic Access",
            disable_o_auth=True,
        )

        CfnOutput(
            self,
            "programmatic-client-id",
            export_name="Programmatic-Client-ID",
            value=client.user_pool_client_id,
        )

        return client

    def add_service_client(self, userpool: cognito.UserPool) -> cognito.UserPoolClient:
        service_scope = cognito.ResourceServerScope(
            scope_name="service",
            scope_description="Scope indicating that this is a service requesting access.",
        )

        m2m_server = userpool.add_resource_server(
            "resource-server",
            identifier="m2m-server",
            scopes=[service_scope],
        )

        client = userpool.add_client(
            "service-access",
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(client_credentials=True),
                scopes=[cognito.OAuthScope.resource_server(m2m_server, service_scope)],
            ),
            generate_secret=True,
            user_pool_client_name="Service Access",
            disable_o_auth=False,
        )

        # secretsmanager.Secret(
        #     self,
        #     "service-access-secret",
        #     secret_name=f"{Stack.of(self).stack_name}/cognito-service-access-client/creds",
        #     secret_string_value=secretsmanager.SecretValue({
        #         client_
        #     }
        # )

        CfnOutput(
            self,
            "service-client-id",
            export_name="Service-Client-ID",
            value=client.user_pool_client_id,
        )
        CfnOutput(
            self,
            "service-client-secret",
            export_name="Service-Client-secret",
            value=self.get_client_secret(userpool, client),
        )

        return client

    def get_client_secret(
        self, userpool: cognito.UserPool, client: cognito.UserPoolClient
    ) -> str:
        # https://github.com/aws/aws-cdk/issues/7225#issuecomment-610299259
        describeCognitoUserPoolClient = cr.AwsCustomResource(
            self,
            "DescribeCognitoUserPoolClient",
            resource_type="Custom::DescribeCognitoUserPoolClient",
            on_create=cr.AwsSdkCall(
                region="us-east-1",
                service="CognitoIdentityServiceProvider",
                action="describeUserPoolClient",
                parameters={
                    "UserPoolId": userpool.user_pool_id,
                    "ClientId": client.user_pool_client_id,
                },
                physical_resource_id=cr.PhysicalResourceId.of(
                    client.user_pool_client_id
                ),
            ),
            policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                resources=cr.AwsCustomResourcePolicy.ANY_RESOURCE,
            ),
        )

        return describeCognitoUserPoolClient.get_response_field(
            "UserPoolClient.ClientSecret"
        )

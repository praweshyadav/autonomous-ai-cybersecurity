from __future__ import annotations

import os
from typing import Any

from neo4j import Driver, GraphDatabase


DEFAULT_NEO4J_URI = os.getenv("NEO4J_URI")
DEFAULT_NEO4J_USERNAME = os.getenv("NEO4J_USERNAME")
DEFAULT_NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
DEFAULT_NEO4J_DATABASE = os.getenv("NEO4J_DATABASE")

if not all(
    (
        DEFAULT_NEO4J_URI,
        DEFAULT_NEO4J_USERNAME,
        DEFAULT_NEO4J_PASSWORD,
        DEFAULT_NEO4J_DATABASE,
    )
):
    raise RuntimeError(
        "Neo4j environment variables are not fully configured."
    )


class Neo4jClient:
    """
    Small infrastructure client for Neo4j.

    Responsibilities:
        - Create and manage the Neo4j driver.
        - Verify database connectivity.
        - Execute parameterized Cypher queries.
        - Close the driver cleanly.

    This class intentionally does not contain cybersecurity
    graph business logic.
    """

    def __init__(
        self,
        uri: str | None = None,
        username: str | None = None,
        password: str | None = None,
        database: str | None = None,
    ) -> None:

        self.uri = (
            uri
            if uri is not None
            else os.getenv(
                "NEO4J_URI",
                DEFAULT_NEO4J_URI,
            )
        )

        self.username = (
            username
            if username is not None
            else os.getenv(
                "NEO4J_USERNAME",
                DEFAULT_NEO4J_USERNAME,
            )
        )

        self.password = (
            password
            if password is not None
            else os.getenv(
                "NEO4J_PASSWORD",
                DEFAULT_NEO4J_PASSWORD,
            )
        )

        self.database = (
            database
            if database is not None
            else os.getenv(
                "NEO4J_DATABASE",
                DEFAULT_NEO4J_DATABASE,
            )
        )

        if not isinstance(self.uri, str) or not self.uri.strip():
            raise ValueError(
                "Neo4j URI cannot be empty."
            )

        if not isinstance(self.username, str) or not self.username.strip():
            raise ValueError(
                "Neo4j username cannot be empty."
            )

        if not isinstance(self.password, str) or not self.password:
            raise ValueError(
                "Neo4j password cannot be empty."
            )

        if not isinstance(self.database, str) or not self.database.strip():
            raise ValueError(
                "Neo4j database cannot be empty."
            )

        self._driver: Driver = GraphDatabase.driver(
            self.uri,
            auth=(
                self.username,
                self.password,
            ),
        )

    @property
    def driver(self) -> Driver:
        """
        Return the underlying Neo4j driver.
        """
        return self._driver

    def verify_connectivity(self) -> None:
        """
        Verify that Neo4j is reachable and authentication works.
        """
        self._driver.verify_connectivity()

    def execute(
        self,
        query: str,
        parameters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Execute a read/write Cypher query and return records as
        dictionaries.

        Parameters are always passed separately from the query
        to avoid constructing Cypher through string interpolation.
        """

        if not isinstance(query, str):
            raise TypeError(
                "query must be a string."
            )

        if not query.strip():
            raise ValueError(
                "query cannot be empty."
            )

        if parameters is None:
            parameters = {}

        if not isinstance(parameters, dict):
            raise TypeError(
                "parameters must be a dictionary."
            )

        with self._driver.session(
            database=self.database
        ) as session:

            result = session.run(
                query,
                parameters,
            )

            return [
                record.data()
                for record in result
            ]

    def close(self) -> None:
        """
        Close the Neo4j driver.
        """
        self._driver.close()

    def __enter__(self) -> "Neo4jClient":
        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ) -> None:
        self.close()

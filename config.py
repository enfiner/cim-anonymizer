# -*- coding: utf-8 -*-
"""Правила обезличивания. Привязка к ЛОКАЛЬНЫМ именам тегов,
поэтому URI пространств имён (cim:, me:, so:) не важны."""

SALT = "cim-anon-salt-v2-2026"
LANGUAGE = "ru"                      # ru / en / любой код lang_<код>.json

RDF_NS = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
RDF_ID = f"{{{RDF_NS}}}ID"
RDF_ABOUT = f"{{{RDF_NS}}}about"
RDF_RESOURCE = f"{{{RDF_NS}}}resource"

CLASS_CATEGORY = {
    "EnergyConsumer": "person", "Customer": "person",
    "CustomerAccount": "person", "CustomerAgreement": "person",
    "Person": "employee", "Employee": "employee",
    "Organisation": "organization", "Organization": "organization",
    "Company": "organization",
}

PROP_RULES = {
    "IdentifiedObject.name": "name_by_category",
    "Naming.name": "name_by_category",
    "IdentifiedObject.aliasName": "object_name",
    "IdentifiedObject.localName": "object_name",
    "IdentifiedObject.pathName": "object_name",
    "IdentifiedObject.description": "free_text",
    "IdentifiedObject.remark": "free_text",
    "IdentifiedObject.mRID": "mrid",
    "IPConnectionPoint.address": "ip",
    "TCPConnectionPoint.port": "port",
    "Person.name": "fio",
    "Person.firstName": "first_name",
    "Person.lastName": "last_name",
    "Person.middleName": "middle_name",
    "Person.email": "email", "Person.email1": "email", "Person.email2": "email",
    "Person.telephone": "phone", "Person.mobile": "phone", "Person.phone": "phone",
    "Person.employeeNumber": "digits",
    "Person.passportNumber": "digits",
    "Organisation.name": "org_name", "Organization.name": "org_name",
    "Organisation.inn": "inn", "Organization.inn": "inn",
    "Organisation.kpp": "digits", "Organization.kpp": "digits",
    "Asset.serialNumber": "digits", "Asset.lotNumber": "digits",
    "Model.description": "free_text",
    "Model.modelingAuthoritySet": "authority",
    "Document.fileName": "file_name",
    "Document.uri": "ext_link", "Document.URL": "ext_link",
    "ElectronicAddress.uri": "ext_link",
}

UNIQUE_CATEGORIES = ("uuid", "object_name", "org_name", "inn", "digits", "ip")

ANON_PORTS = True
SHIFT_COORDS = False

import re
PATTERNS_PDN = [
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("phone", re.compile(r"(?:\+7|8)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}")),
    ("inn",   re.compile(r"\b\d{12}\b|\b\d{10}\b")),
    ("ip",    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]

COORD_PROPS = {"PositionPoint.xPosition", "PositionPoint.yPosition"}
#!/usr/bin/env sh

CURDIR=$(dirname $0)

unset PROJECT_NAME
while [ -z ${PROJECT_NAME} ]; do
    read -p "Enter Project Name: " PROJECT_NAME
    [ -z ${PROJECT_NAME} ] && echo "ERROR: Project name is required!";
done

read -p "Enter Project Version (default=0.1.0): " PROJECT_VERSION
[ -z ${PROJECT_VERSION} ] && PROJECT_VERSION="0.1.0";

INCLUDE_FILE="${CURDIR}/cb.hpp"
cat ${CURDIR}/cb.cpp.template | sed "s/\${PROJECT_NAME}/\"${PROJECT_NAME}\"/g" | sed "s/\${PROJECT_VERSION}/\"${PROJECT_VERSION}\"/g" | sed "s/\${INCLUDE_FILE}/\"${INCLUDE_FILE}\"/g" >> ./cb.cpp



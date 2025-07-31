#!/bin/sh

INSTALL_PREFIX=${INSTALL_PREFIX:-""}
INSTALL=${INSTALL:-"install"}
INSTALL_OWNER=${INSTALL_OWNER:-"-o root -g root"}
DESTDIR=${DESTDIR:-"/usr/local"}

if [ "${DESTDIR}" = "/" ]; then
  BINDIR="/usr/bin"
  ETCDIR="/etc"
  MAN_DIR="/usr/share/man"
else
  BINDIR="${DESTDIR}/bin"
  ETCDIR="${DESTDIR}/etc"
  MAN_DIR="${DESTDIR}/share/man"
fi

echo "Installing manpages"
"${INSTALL}" -d -m 755 ${INSTALL_OWNER} "${INSTALL_PREFIX}${MAN_DIR}/man8" | exit 1
"${INSTALL}" -m 644 ${INSTALL_OWNER} vtunngd.8 "${INSTALL_PREFIX}${MAN_DIR}/man8" | exit 1
"${INSTALL}" -d -m 755 ${INSTALL_OWNER} "${INSTALL_PREFIX}${MAN_DIR}/man5" | exit 1
"${INSTALL}" -m 644 ${INSTALL_OWNER} vtunngd.conf.5 "${INSTALL_PREFIX}${MAN_DIR}/man5" | exit 1
rm -f "${INSTALL_PREFIX}${MAN_DIR}/man8/vtunng.8" | exit 1
ln -s vtunngd.8 "${INSTALL_PREFIX}${MAN_DIR}/man8/vtunng.8" | exit 1

echo "Installing configuration file"
"${INSTALL}" -d -m 755 ${INSTALL_OWNER} "${INSTALL_PREFIX}${ETCDIR}" | exit 1
if [ ! -f "${INSTALL_PREFIX}${ETCDIR}/vtunngd.conf" ]; then
  "${INSTALL}" -m 600 ${INSTALL_OWNER} vtunngd.conf "${INSTALL_PREFIX}${ETCDIR}" | exit 1;
fi

echo "Installing binary"
"${INSTALL}" -d -m 755 ${INSTALL_OWNER} "${INSTALL_PREFIX}${BINDIR}" | exit 1
"${INSTALL}" -m 755 ${INSTALL_OWNER} target/release/vtunngd "${INSTALL_PREFIX}${BINDIR}" | exit 1

echo "Installation successful"

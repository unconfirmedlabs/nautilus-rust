#!/bin/sh
set -eu

if [ "$#" -lt 1 ]; then
	echo "usage: $0 <package> [target] [cargo tree args...]" >&2
	exit 2
fi

package=$1
shift
if [ "$#" -gt 0 ]; then
	case $1 in
	-*) ;;
	*)
		target=$1
		shift
		set -- --target "$target" "$@"
		;;
	esac
fi

if ! cargo tree --locked -p "$package" -e normal --prefix none "$@" | grep -q '^nautilus v'; then
	echo "error: $package does not depend on nautilus; check the package name" >&2
	exit 1
fi

tree=$(cargo tree --locked -p "$package" -e normal,features -i nautilus --prefix none "$@")

if printf '%s\n' "$tree" | grep -q '^nautilus feature "test-utils"'; then
	echo "error: $package enables nautilus/test-utils; refusing to build an enclave with a public development identity" >&2
	exit 1
fi

echo "ok: $package does not enable nautilus/test-utils"

import argparse
import os.path
import sys

from fileshash import FilesHash, SUPPORTED_ALGORITHMS


default_hash_algorithm = 'sha256'

def create_parser():
    parser = argparse.ArgumentParser(
        description="Tool for calculating the checksum / hash of a file or directory."
    )
    parser.add_argument(
        u"-a",
        u"--algorithm",
        help=u"Checksum/hash algorithm to use.  Valid values are: {0}.  Defaults to \"{1}\"".format(
            ", ".join(['"' + a + '"' for a in SUPPORTED_ALGORITHMS]),
            default_hash_algorithm
        ),
        default=default_hash_algorithm
    )

    parser_group = parser.add_mutually_exclusive_group(required=True)
    parser_group.add_argument(
        u"-t",
        u"--cathash",
        nargs='+',
        help=u"Process multiple files to yield a single hash value."
        )
    parser_group.add_argument(
        u"filenames",
        default=[],
        nargs='*',
        help=u"files to calculate the checksum/hash on"
        )

    return parser


def process_cathash(filenames, hasher):
    result = hasher.cat_join(filenames)
    print("{0} *{1}".format(result, " ".join(filenames)))


def process_files(filenames, hasher):
    for filename in filenames:
        if not os.path.isfile(filename):
            print("ERROR: Unable to read file: {0}".format(filename))
            sys.exit(1)
        result = hasher.full_parcel(filename)
        print("{0} *{1}".format(result, filename))


def main():
    args = create_parser().parse_args()

    if not args.algorithm.lower() in SUPPORTED_ALGORITHMS:
        print("ERROR: Unknown checksum/hash algorithm: {0}".format(args.algorithm))
        parser.print_help()
        sys.exit(1)

    hasher = FilesHash(args.algorithm.lower())
    if args.cathash:
        process_cathash(args.cathash, hasher)
    else:
        process_files(args.filenames, hasher)


if __name__ == "__main__":
    main()

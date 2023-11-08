import argparse
import base64
import shutil
import socket
from datetime import datetime
from urllib.parse import urljoin

import certifi
import requests
from OpenSSL import SSL, crypto
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.x509 import ocsp

# The set that keeps track of which certificate was checked during certificate verification process
# We need it for preventing that `verify()` callback checks the same certificate twice
verified_depth_set = set()

# The flag that indicates whether verifying certificates is successful or not
is_verified = True


class Color:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'


def print_with_color(text, color):
    """
    Print a text with `color`
    :param text: The text to print
    :param color: The color to set
    """

    print(color + text + Color.RESET)


def print_header(text):
    """
    Print a header text describing the current process
    :param text: The header text to print
    """

    # The width of the terminal
    columns, _ = shutil.get_terminal_size(fallback=(80, 24))

    # The length of '=' character (on each side)
    remaining_columns = max(40, columns - len(text) - 2) // 2

    print_with_color(f'{"=" * remaining_columns} {text} {"=" * remaining_columns}\n', Color.CYAN)


def dump_certificate(certificate, dump_type=crypto.FILETYPE_ASN1):
    """
    Dump a pyOpenSSL's X509 object into a buffer encoded with `dump_type`
    :param certificate: The pyOpenSSL's X509 object
    :param dump_type: The encoding type (ASN1(default), PEM, or TEXT)
    :return: The buffer with the dumped certificate in
    """

    return crypto.dump_certificate(dump_type, certificate)


def convert_certificate(certificate):
    """
    Convert a pyOpenSSL's X509 object into a cryptography's Certificate object
    In this file, for distinction, name X509 object as `certificate` and Certificate object as `cert`
    :param certificate: The pyOpenSSL's X509 object
    :return: The cryptography's Certificate object
    """

    return x509.load_der_x509_certificate(dump_certificate(certificate))


def get_subject_name(certificate):
    """
    Get a slash delimited string for subject from pyOpenSSL's X509 object
    :param certificate: The pyOpenSSL's X509 object
    :return: The slash delimited string for subject
    """

    cert = convert_certificate(certificate)

    return ''.join([
        f'/{attr.rfc4514_attribute_name}={attr.value}'
        for attr in cert.subject
        if attr.oid in x509.name._NAMEOID_TO_NAME
    ])


def get_issuer_name(certificate):
    """
    Get a slash delimited string for issuer from pyOpenSSL's X509 object
    :param certificate: The pyOpenSSL's X509 object
    :return: The slash delimited string for issuer
    """

    cert = convert_certificate(certificate)

    return ''.join([
        f'/{attr.rfc4514_attribute_name}={attr.value}'
        for attr in cert.issuer
        if attr.oid in x509.name._NAMEOID_TO_NAME
    ])


def print_certificate_basic(certificate):
    """
    Print the certificate's information simply (subject, issuer)
    :param certificate: The pyOpenSSL's X509 object
    """

    print(f'Subject: {get_subject_name(certificate)}')
    print(f'Issuer: {get_issuer_name(certificate)}')
    if hasattr(certificate, 'replaced'):
        print_with_color(
            '→ It was the cross-signed certificate, and replaced with the self-signed certificate in local.',
            Color.YELLOW
        )
    print()


def print_certificate_detail(certificate):
    """
    Print the certificate's information in more detail
    :param certificate: The pyOpenSSL's X509 object
    """

    print(dump_certificate(certificate, dump_type=crypto.FILETYPE_TEXT).decode())


def get_root_certificate(name):
    """
    Get Root CA's certificate whose name is `name`
    If cross-signed, it can return another certificate with the same name, which is self-signed
    In that case, replace the cross-signed certificate with the self-signed certificate in local
    :param name: The string whose format equals to the string returned by `get_subject_name()` or `get_issuer_name()`
    :return: The pyOpenSSL's X509 object or None
    """

    # The path where the file containing Root CA's certificates exists
    root_certificates_path = certifi.where()

    # Open the file
    with open(root_certificates_path, 'r') as root_certificates_file:
        # Split the certificates
        for root_certificate_str in root_certificates_file.read().split('\n-----END CERTIFICATE-----\n')[:-1]:
            # Construct individual certificate's PEM bytes
            root_certificate_str += '\n-----END CERTIFICATE-----\n'
            root_certificate_str = root_certificate_str.lstrip()
            root_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, root_certificate_str.encode())

            # If matched
            if get_subject_name(root_certificate) == name:
                return root_certificate

    # Not matched
    return None


def replace_certificate(last_certificate):
    """
    Replace the last certificate with the self-signed certificate in local (if necessary)
    :param last_certificate: The pyOpenSSL's X509 object
    :return: The pyOpenSSL's X509 object
    """

    # If the last certificate is not self-signed and the issuer's certificate is not in local
    if (
        get_subject_name(last_certificate) != get_issuer_name(last_certificate) and
        not get_root_certificate(get_issuer_name(last_certificate))
    ):
        root_certificate = get_root_certificate(get_subject_name(last_certificate))

        # Replace the cross-signed certificate (if any) with the self-signed certificate in local
        if root_certificate:
            root_certificate.replaced = True
            return root_certificate

    # Don't replace
    return last_certificate


def verify_signature(certificate, issuer_certificate):
    """
    Verify the signature of `certificate` by the public key in `issuer_certificate`
    :param certificate: The pyOpenSSL's X509 object
    :param issuer_certificate: The pyOpenSSL's X509 object
    """

    cert = convert_certificate(certificate)
    issuer_cert = convert_certificate(issuer_certificate)
    issuer_public_key = issuer_cert.public_key()

    # If the signature is generated with RSA
    if isinstance(issuer_public_key, rsa.RSAPublicKey):
        issuer_public_key.verify(
            cert.signature,  # The signature to verify
            cert.tbs_certificate_bytes,  # The payload that was signed by the issuer's private key
            cert.signature_algorithm_parameters,  # PKCS1v15, PSS
            cert.signature_hash_algorithm
        )

    # If the signature is generated with DSA
    elif isinstance(issuer_public_key, dsa.DSAPublicKey):
        issuer_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            cert.signature_hash_algorithm
        )

    # If the signature is generated with ECDSA
    elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
        issuer_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            cert.signature_algorithm_parameters  # ECDSA
        )

    # Otherwise
    else:
        issuer_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes
        )


def verify(connection, certificate, error_no, depth, return_code):
    """
    Verify each level of certificate recursively (from the root)
    :param connection: The SSL connection object
    :param certificate: The pyOpenSSL's X509 object
    :param error_no: Not used here
    :param depth: The depth in the certificate chain (leaf certificate is 0)
    :param return_code: Not used here
    :return: Always True, for continuing certificate verification process
    """

    global verified_depth_set, is_verified

    # Prevent checking the same certificate twice
    if depth in verified_depth_set:
        return True
    else:
        verified_depth_set.add(depth)

    # The certificate chain
    certificate_chain = connection.get_peer_cert_chain()

    # The last certificate (root in the certificate chain)
    if depth == len(certificate_chain) - 1:
        # Replace the last certificate with the self-signed certificate in local (if necessary)
        certificate = replace_certificate(certificate)

    # Print the certificate's information simply
    print_with_color(f'[Certificate at depth: {depth}]\n', Color.BOLD)
    print_certificate_basic(certificate)

    # When the parent certificate exists
    if depth < len(certificate_chain) - 1:
        # Get the issuer's certificate from the certificate chain
        issuer_certificate = certificate_chain[depth + 1]

    # When the parent certificate does not exist
    else:
        # Get the issuer's certificate from local
        issuer_certificate = get_root_certificate(get_issuer_name(certificate))
        if not issuer_certificate:
            is_verified = False
            print_with_color('Failed in verifying signature. No issuer\'s certificate is in local.', Color.RED)

    # Verify the signature by the public key in the issuer's certificate
    if issuer_certificate:
        try:
            verify_signature(certificate, issuer_certificate)
        except:
            is_verified = False
            print_with_color(f'Failed in verifying signature. The signature is invalid.', Color.RED)
        else:
            print_with_color('Succeeded in verifying signature.', Color.GREEN)

    # Check the validity period
    cert = convert_certificate(certificate)
    before, after = cert.not_valid_before, cert.not_valid_after
    if before <= datetime.now() <= after:
        print_with_color(f'Succeeded in verifying validity period. ({before} ~ {after})', Color.GREEN)
    else:
        is_verified = False
        if datetime.now() < before:
            print_with_color(f'Failed in verifying validity period. It will be valid from {before}.', Color.RED)
        else:
            print_with_color(f'Failed in verifying validity period. It was expired at {after}.', Color.RED)

    print()

    # Continue certificate verification process
    return True


if __name__ == '__main__':
    # Set command arguments (host: positional, -v/o: optional)
    parser = argparse.ArgumentParser()
    parser.add_argument('host', help='the name of the host to verify certificate')
    parser.add_argument('-v', action='store_true', help='print each certificate\'s information in more detail')
    parser.add_argument('-o', action='store_true', help='save each certificate\'s information as a .pem file')

    # Read command arguments
    args = parser.parse_args()
    host = args.host
    verbose = bool(args.v)
    save = bool(args.o)

    # Create a new SSL context (Here, the location of the trust store is set automatically)
    context = SSL.Context(SSL.TLS_METHOD)

    # Customize certificate verification logic, which is implemented in `verify()` callback
    context.set_verify(SSL.VERIFY_PEER, verify)

    # Set up the SSL connection to the remote host
    connection = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    connection.set_connect_state()

    # Set the SNI hostname
    connection.set_tlsext_host_name(host.encode())

    # Attempt to connect
    try:
        connection.connect((host, 443))
    except Exception as e:
        print_with_color(f'Failed in connecting to the remote host. {e}\n', Color.RED)
        exit(0)

    # Attempt to do the TLS/SSL handshake (including certificate verification process)
    try:
        print_header('Verifying Certificates')
        connection.do_handshake()
    except Exception as e:
        print_with_color(f'Failed in establishing the SSL connection. {e}\n', Color.RED)
        exit(0)

    # Fetch the certificate chain
    certificate_chain = connection.get_peer_cert_chain()
    if not certificate_chain:
        print_with_color('Failed in fetching the certificates.\n', Color.RED)
        exit(0)

    # Replace the last certificate with the self-signed certificate in local (if necessary)
    certificate_chain[-1] = replace_certificate(certificate_chain[-1])

    print_header('Printing Certificates Basic')

    # Print each certificate's information
    leaf_ocsp_uris = None
    for depth, certificate in enumerate(certificate_chain):
        # Print the certificate's information simply
        print_with_color(f'[Certificate at depth: {depth}]\n', Color.BOLD)
        print_certificate_basic(certificate)

        # The certificate
        cert = convert_certificate(certificate)

        crl_distribution_points = []
        try:
            # Get CRL_DISTRIBUTION_POINTS extension from the certificate
            CRL_DISTRIBUTION_POINTS = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.CRL_DISTRIBUTION_POINTS
            )
        except x509.ExtensionNotFound:
            pass
        else:
            # Extract CRL distribution points
            for distribution_point in CRL_DISTRIBUTION_POINTS.value:
                crl_distribution_points.extend([x.value for x in distribution_point.full_name])

        # Print CRL distribution points (if any)
        if crl_distribution_points:
            print('CRL distribution points obtained from \'CRL_DISTRIBUTION_POINTS\' extension:')
            print('\n'.join(crl_distribution_points) + '\n')
        else:
            print('No CRL distribution points are found.\n')

        ocsp_uris = []
        try:
            # Get AUTHORITY_INFORMATION_ACCESS extension from the certificate
            AUTHORITY_INFORMATION_ACCESS = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
        except x509.ExtensionNotFound:
            pass
        else:
            # Extract OCSP responder URIs
            for access_description in AUTHORITY_INFORMATION_ACCESS.value:
                if access_description.access_method == x509.AuthorityInformationAccessOID.OCSP:
                    ocsp_uris.append(access_description.access_location.value)

        # Print OCSP responder URIs (if any)
        if ocsp_uris:
            print('OCSP responder URIs obtained from \'AUTHORITY_INFORMATION_ACCESS\' extension:')
            print('\n'.join(ocsp_uris) + '\n')
        else:
            print('No OCSP responder URIs are found.\n')

        # Remember OCSP responder URIs, for checking revocation
        if depth == 0 and ocsp_uris:
            leaf_ocsp_uris = ocsp_uris

    # Print each certificate's information in more detail
    if verbose:
        print_header('Printing Certificates Detail')

        for depth, certificate in enumerate(certificate_chain):
            print_with_color(f'[Certificate at depth: {depth}]\n', Color.BOLD)
            print_certificate_detail(certificate)

    # Save each certificate's information as a file
    if save:
        print_header('Saving Certificate Files')

        for depth, certificate in enumerate(certificate_chain):
            filename = f'depth{depth}.pem'

            with open(filename, 'wb') as file:
                file.write(dump_certificate(certificate, dump_type=crypto.FILETYPE_PEM))

            print(f'Saved depth-{depth} certificate to \'{filename}\'.\n')

    print_header('Checking Revocation (OCSP)')

    # Checking revocation is not possible, since there are no OCSP responder URIs
    if not leaf_ocsp_uris:
        print_with_color('Checking revocation is not possible, since there are no OCSP responder URIs.\n', Color.RED)
        exit(0)

    # Print the warning message if verifying certificates failed
    if not is_verified:
        print_with_color('Failed in verifying certificates, so this check can be meaningless.\n', Color.YELLOW)

    # Check revocation by OCSP
    if leaf_ocsp_uris:
        certificate = certificate_chain[0]
        cert = convert_certificate(certificate)

        # The issuer's certificate
        if len(certificate_chain) > 1:
            issuer_certificate = certificate_chain[1]
        else:
            issuer_certificate = get_root_certificate(get_issuer_name(certificate))
            if not issuer_certificate:
                print_with_color('Failed in checking OCSP. No issuer\'s certificate is in local.\n', Color.RED)
                exit(0)
        issuer_cert = convert_certificate(issuer_certificate)

        # Prepare OCSP request
        ocsp_req_builder = ocsp.OCSPRequestBuilder()
        ocsp_req_builder = ocsp_req_builder.add_certificate(cert, issuer_cert, hashes.SHA1())
        ocsp_req = ocsp_req_builder.build()
        ocsp_req_path = base64.b64encode(ocsp_req.public_bytes(serialization.Encoding.DER))

        # Send OCSP request for each OCSP responder URI
        for ocsp_uri in leaf_ocsp_uris:
            print(f'Request to {ocsp_uri}...\n')

            try:
                res = requests.get(urljoin(ocsp_uri + '/', ocsp_req_path.decode('ascii')))
            except:
                print_with_color('Failed in connecting to the OCSP server.\n', Color.RED)
                break

            if not res.ok:
                print_with_color(
                    f'Failed in fetching valid response from the OCSP server(status code: {res.status_code}).\n',
                    Color.RED
                )
                break

            # Parse the response
            ocsp_res = ocsp.load_der_ocsp_response(res.content)

            # Checking OCSP failed for some reason
            if ocsp_res.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
                if ocsp_res.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST:
                    print_with_color(
                        'Failed in checking OCSP. The given request cannot be parsed.\n',
                        Color.RED
                    )
                elif ocsp_res.response_status == ocsp.OCSPResponseStatus.INTERNAL_ERROR:
                    print_with_color(
                        'Failed in checking OCSP. The server is currently experiencing operational problems.\n',
                        Color.RED
                    )
                elif ocsp_res.response_status == ocsp.OCSPResponseStatus.TRY_LATER:
                    print_with_color(
                        'Failed in checking OCSP. The server is overloaded.\n',
                        Color.RED
                    )
                elif ocsp_res.response_status == ocsp.OCSPResponseStatus.TRY_LATER:
                    print_with_color(
                        'Failed in checking OCSP. The server is overloaded, so try again later.\n',
                        Color.RED
                    )
                elif ocsp_res.response_status == ocsp.OCSPResponseStatus.SIG_REQUIRED:
                    print_with_color(
                        'Failed in checking OCSP. The server requires signed OCSP requests.\n',
                        Color.RED
                    )
                elif ocsp_res.response_status == ocsp.OCSPResponseStatus.UNAUTHORIZED:
                    print_with_color(
                        'Failed in checking OCSP. You queried for a certificate for which the server is unaware or '
                        'an issuer for which the responder is not authoritative.\n',
                        Color.RED
                    )
                break

            # Good (Not revoked)
            if ocsp_res.certificate_status == ocsp.OCSPCertStatus.GOOD:
                print_with_color(f'Certificate Status: GOOD\n', Color.GREEN)

            # Revoked
            elif ocsp_res.certificate_status == ocsp.OCSPCertStatus.REVOKED:
                print_with_color(f'Certificate Status: REVOKED (at {ocsp_res.revocation_time})\n', Color.RED)

            # Unknown
            else:
                print_with_color(f'Certificate Status: UNKNOWN\n', Color.RED)

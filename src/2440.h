/*
 * Copyright (c) 2020 Felicity Janet Meadows
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdint.h>

#define SALT_SIZE       (8u)

/* S2K structures */

enum string_to_key
{
    SimpleS2K,
    SaltedS2K,
    ReservedS2K,
    IteratedSaltedS2K
};
struct salted_s2k
{
    uint8_t     S2K_type;
    uint8_t     hash_algorithm;
    uint8_t     salt[SALT_SIZE];
    uint8_t     count;
};

/***************************************************************************/
/* Packet definitions                                                      */
/***************************************************************************/

#define PKT_INDICATED   (1u<<7)
#define PKT_FORMAT_NEW  (1u<<6)
#define PKT_OLD_PACKET  (((1u<<4) - 1u)<<2)
#define PKT_OLD_LENGTH   ((1u<<2) - 1u)
#define PKT_OLD_PKT_SHF  (2u)
#define PKT_NEW_PACKET   ((1u<<6) - 1u)

enum old_packet_len
{
    OldOneOctet,
    OldTwoOctet,
    OldFourOctet,
    OldPartial
};

#define PKT_LEN_ONE_MAX (191u)
#define PKT_LEN_TWO_MAX (8383u)
#define PKT_LEN_LEADING (255u)
#define PKT_LEN_FIVE_MAX (UINT16_T_MAX)

#define PKT_LEN_PT      (224u)
#define PKT_LEN_PT_MASK (0x1f)
#define PKT_LEN_PT_CONVERT(x) (1ul << ((x) & 0x1f))

enum packet_tags
{
    PktReserved,
    PktPKESKP,
    PktSignature,
    PktSKESKP,
    PktOnePassSignature,
    PktSecretKey,
    PktPublicKey,
    PktSecretSubkey,
    PktCompressedData,
    PktSymmetricEncData,
    PktMarker,
    PktLiteral,
    PktTrust,
    PktUserID,
    PktPublicSubkey,
    PktNone1,
    PktNone2,
    PktUserAttribute,
    PktSymEncIntegrityProtData,
    PktMDC
};

/***************************************************************************/
/* Signature definitions                                                   */
/***************************************************************************/

#define SIG_BINARY_DOC    (0x00)
#define SIG_CANON_TEXT	  (0x01)
#define SIG_STANDALONE	  (0x02)
#define SIG_CERT_GENERIC  (0x10)
#define SIG_CERT_PERSONA  (0x11)
#define SIG_CERT_CASUAL   (0x12)
#define SIG_CERT_POSITIVE (0x13)
#define SIG_SUBKEY_BIND   (0x18)
#define SIG_PRIMARY_BIND  (0x19)
#define SIG_DIRECT        (0x1f)
#define SIG_REVOKE_KEY    (0x20)
#define SIG_REVOKE_SUBKEY (0x28)
#define SIG_REVOKE_CERT   (0x30)
#define SIG_TIMESTAMP     (0x40)
#define SIG_THIRD_PARTY   (0x50)

#define SIG_VERSION_3_BAS (19u)
#define SIG_VERSION_4_BAS (10u)
#define SIG_SUBPACKET_LEN (2u)

struct sig_subpacket
{
    uint8_t length;
    uint8_t type;
};

/***************************************************************************/
/* Subpacket definitions                                                   */
/***************************************************************************/

enum sub_packet_tags
{
    SubPktSigCreation = 2,
    SubPktSigExpiration,
    SubPktExportable,
    SubPktRegex,
    SubPktRevocable,
    SubPktKeyExpiration = 9,
    SubPktPlaceholder,
    SubPktSymmetricAlg,
    SubPktRevocationKey,
    SubPktIssuerKeyID = 16,
    SubPktNotationData = 20,
    SubPktHashAlg,
    SubPktCompressionAlg,
    SubPktKeyServer,
    SubPktPrefKeyServer,
    SubPktPrimaryUserID,
    SubPktPolicyURI,
    SubPktKeyFlags,
    SubPktSignerUserID,
    SubPktRevokeReason,
    SubPktFeatures,
    SubPktSigTarget,
    SubPktSigEmbedded
};

#define SUB_PKT_NUM_TAGS (32u)
#define SUB_PKT_CRITICAL (0x80)
uint8_t sub_pkt_fixed_len[SUB_PKT_NUM_TAGS] =
{
    0, 0,
    4, 4, 1, 0, 1,
    0, 0, 
    4, 0, 0, 22,
    0, 0, 0,
    8,
    0, 0, 0,
    8, 0, 0, 0, 1, 0, 0, 0, 1, 0, 2, 0
};
uint8_t sub_pkt_variable[SUB_PKT_NUM_TAGS] =
{
    0, 0,
    0, 0, 0, 1, 0,
    0, 0, 
    0, 1, 1, 0,
    0, 0, 0,
    0,
    0, 0, 0,
    1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1
};
					
#define SUB_PKT_LEN_SIG_CREATION        (4u)
#define SUB_PKT_LEN_SIG_EXPIRATION      (4u)

/***************************************************************************/
/* Other definitions                                                       */
/***************************************************************************/

enum pub_key_tags
{
    PKAlgEncryptAndSign = 1,
    PKAlgEncryptOnly,
    PKAlgSignOnly,
    PKAlgElGamal = 16,
    PKAlgDSA,
    PKAlgECCRsv,
    PKAlgECDSARsv,
    PKAlgReserved,
    PKAlgDHRsv
};

enum sym_key_tags
{
    SKAlgPlaintext,
    SKAlgIDEA,
    SKAlgTripleDES,
    SKAlgCast5,
    SKAlgBlowfish,
    SKAlgAES128 = 7,
    SKAlgAES192,
    SKAlgAES256,
    SKAlgTwofish256
};

enum compression_tags
{
    CAlgUncompress,
    CAlgZIP,
    CAlgZLib,
    CAlgBZip2
};

enum hash_tags
{
    HashAlgMD5 = 1,
    HashAlgSHA1,
    HashAlgRIPEMD160,
    HashAlgSHA256 = 8,
    HashAlgSHA384,
    HashAlgSHA512,
    HashAlgSHA224
};

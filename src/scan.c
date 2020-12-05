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
#include <stdio.h>
#include <byteswap.h>

#include "2440.h"

extern uint16_t buf_read (uint8_t index, uint8_t * buf, uint16_t size);
extern uint16_t buf_write (uint8_t index, const uint8_t * buf, uint16_t size);
extern uint8_t  mark_start (uint8_t flag);
extern uint8_t  mark_end (uint8_t flag);
extern uint8_t  mark_buffer (uint8_t flag, uint8_t *pMark);
extern uint8_t *pop_marker (uint8_t *flag);
extern uint8_t *last_marker (uint8_t *flag);

#define FALSE           (0u)
#define TRUE            (!FALSE)
#define MAXIMUM_GRAB    (1024u)

static uint8_t grabbing[MAXIMUM_GRAB];
static  int8_t sub_pkt_tag_txt [][17] =
{
    "XXX             ",
    "XXX             ",
    "SigCreation     ",
    "SigExpiration   ",
    "Exportable      ",
    "Trust           ",
    "Regex           ",
    "Revocable       ",
    "XXX             ",
    "KeyExpiration   ",
    "Placeholder     ",
    "SymmetricAlg    ",
    "RevocationKey   ",
    "XXX             ",
    "XXX             ",
    "XXX             ",
    "IssuerKeyID     ",
    "XXX             ",
    "XXX             ",
    "XXX             ",
    "NotationData    ",
    "HashAlg         ",
    "CompressionAlg  ",
    "KeyServer       ",
    "PrefKeyServer   ",
    "PrimaryUserID   ",
    "PolicyURI       ",
    "KeyFlags        ",
    "SignerUserID    ",
    "RevokeReason    ",
    "Features        ",
    "SigTarget       ",
    "SigEmbedded     "
};

#define SUB_PKT_NUM_TAGS (32u)
/* 1 - UINT32_T_MAX only */
static void display_hex (int8_t *disp_str, uint8_t *buf, uint32_t size)
{
uint8_t mod_remain;
uint32_t i, j;

    if (size == 0) return;
    mod_remain = size % 16ul;

    i = 0ul;
    if (size / 16ul)
    {
        for (i = 0ul; i < (size / 16ul); i++)
        {
             printf ("%s: ", disp_str);
             for (j = 0ul; j < 16ul; j++)
             {
                 printf ("%02x ", buf[i*16ul+j]);
             }
             printf ("\n");
        }
   }
   if (mod_remain)
   {
       printf ("%s: ", disp_str);
       for (j = 0ul; j < (uint32_t)mod_remain; j++)
       {
           printf ("%02x ", buf[i*16ul+j]);
       }
       printf ("\n");
   }
}

/********************************************************************************/
/*                                                                              */
/* grab_new_s_pkt_head                                                          */
/* INPUTS: fp - open pgp file containing packets                                */
/*         mainPkt - whether this is a packet or a sub-packet                   */
/* RETURN: number of bytes to transferred                                       */
/* OUTPUT: pPartial - whether this a partial packet or not                      */
/*         pLength - the length of the packet                                   */
/*                                                                              */
/* Grab the new packet header or sub-packet header, and the return the length   */
/* of the the rest of the packet to be expected.                                */
/*                                                                              */
/********************************************************************************/
  
static uint8_t grab_new_s_pkt_head (FILE *fp, uint8_t mainPkt, uint8_t *pPartial, uint32_t *pLength)
{
uint8_t val;
uint8_t transferred;
uint32_t length;

    *pPartial   = FALSE;
    transferred = fread (&val, 1u, sizeof(uint8_t), fp);
    if (transferred != sizeof(uint8_t)) return transferred;
    length = val;
    if ((val > PKT_LEN_ONE_MAX) &&
             (val < (mainPkt ? PKT_LEN_PT : PKT_LEN_LEADING)))
    {
        transferred += fread (&val, 1u, sizeof(uint8_t), fp);
        if (transferred != sizeof(uint8_t)*2) return transferred;
        length =   val - (PKT_LEN_ONE_MAX + 1);
        length <<= 8;
        length +=  val;
        length +=  PKT_LEN_ONE_MAX + 1;
    }
    else if (val == PKT_LEN_LEADING)
    {
        transferred += fread (&length, 1u, sizeof(uint32_t), fp);
        if (transferred != sizeof(uint8_t)+sizeof(uint32_t))
        {
            return transferred;
        }
//        bswap_32 (length);
        length = __bswap_constant_32 (length);
    }
    else if ((val >= PKT_LEN_PT) && mainPkt) 
    {
        /* this could be replaced with the macro */
        length    = (1ul << (val & PKT_LEN_PT_MASK));
        *pPartial = TRUE;
    }
    *pLength = length;
}

static uint8_t grab_sub_pkt_head (FILE *fp, uint32_t *pLength)
{
uint8_t dummy;

    return grab_new_s_pkt_head (fp, FALSE, &dummy, pLength);
}

/********************************************************************************/
/*                                                                              */
/* grab_packet_head                                                             */
/* INPUTS: fp - open pgp file containing packets                                */
/* RETURN: number of bytes to transferred                                       */
/* OUTPUT: pTag - the tag of the packet                                         */
/*         pPartial - whether this packet is incomplete/partial                 */
/*         pLength - the length of the packet (NB may be partial)               */
/*                                                                              */
/* Grab the packet header and return the tag, partial indicator and length of   */
/* the remaining packet                                                         */
/*                                                                              */
/********************************************************************************/

static uint8_t grab_packet_head (FILE *fp, uint8_t *pTag, uint8_t *pPartial, uint32_t *pLength)
{
uint8_t val;
uint8_t transferred = 0u;
uint16_t old_length;
uint32_t length;
enum old_packet_len op_len;

    *pTag     = 0u;
    *pPartial = FALSE;
    *pLength  = (0ul);
    transferred += fread (pTag, 1u, sizeof(uint8_t), fp);
    if (transferred != sizeof(uint8_t)) return transferred;
    if (!(*pTag & PKT_INDICATED))
    {
        return (sizeof(uint8_t));
    }
    if (*pTag & PKT_FORMAT_NEW)
    {
        transferred  = grab_new_s_pkt_head (fp, TRUE, pPartial, pLength) + 1; 
        *pTag       &= PKT_NEW_PACKET;
    }
    else
    {
        op_len = (*pTag & PKT_OLD_LENGTH);
        switch (op_len)
        {
            case OldOneOctet:
                transferred += fread (&val, 1u, sizeof(uint8_t), fp);
                if (transferred != sizeof(uint8_t)*2) return transferred;
                length = val;
                break;
            case OldTwoOctet:
                transferred += fread (&old_length, 1u, sizeof(uint16_t), fp);
                if (transferred != sizeof(uint8_t)+sizeof(uint16_t))
                {
                    return transferred;
                }
//                bswap_16 (old_length);
                old_length = __bswap_constant_16 (old_length);
                length = old_length;
                break;
            case OldFourOctet:
                transferred += fread (&length, 1u, sizeof(uint32_t), fp);
                if (transferred != sizeof(uint8_t)+sizeof(uint32_t))
                {
                    return transferred;
                }
//                bswap_32 (length);
                length = __bswap_constant_32 (length);
                break;
            case OldPartial:
                *pPartial = TRUE;
                break;
            default:
                break;
        }
        *pTag &=  PKT_OLD_PACKET;
        *pTag >>= PKT_OLD_PKT_SHF;
        *pLength = length;
    }    
    return transferred;
}

static uint16_t grab_hashed (FILE *fp)
{
uint16_t sz_hashed;
uint8_t  val;
uint8_t  transferred = 0u;
uint32_t packet_offset;
uint32_t subpacket_size;
uint8_t  h_index=48u;
int8_t   h[4]="h  ";

     transferred += fread (&val, 1u, sizeof(uint8_t), fp);
     sz_hashed    = val;
     sz_hashed  <<= 8u;
     transferred += fread (&val, 1u, sizeof(uint8_t), fp);
     sz_hashed   += val;
     if (transferred != sizeof(uint16_t))
     {
         return ;
     }
     packet_offset  = 0ul;
     while (packet_offset < (uint32_t)sz_hashed)
     {
//          grab_sub_pkt_head (fp, &subpacket_size);          
          fread (&val, 1u, sizeof(uint8_t), fp);
          subpacket_size =  val;
          if (fread (grabbing, 1u, subpacket_size, fp) == subpacket_size)
          {
              if (*grabbing < 32)
              {
                  printf (sub_pkt_tag_txt[*grabbing]);
              }
              if (*grabbing == 24)
              {
                  grabbing[subpacket_size]='\0';
                  printf ("KEY:= %s\n", grabbing+1);
              }
              h[2] = h_index++;
              display_hex (h, grabbing, subpacket_size); 
              packet_offset += subpacket_size + 1;
          }
     }
     return sz_hashed + 2;
}

static uint16_t grab_unhashed (FILE *fp)
{
uint16_t sz_unhashed;
uint8_t  val;
uint8_t  transferred = 0u;
uint32_t packet_offset;
uint32_t subpacket_size;
uint8_t  uh_index=48u;
int8_t   uh[4]="uh ";

     transferred += fread (&val, 1u, sizeof(uint8_t), fp);
     sz_unhashed    = val;
     sz_unhashed  <<= 8u;
     transferred += fread (&val, 1u, sizeof(uint8_t), fp);
     sz_unhashed   += val;
     if (transferred != sizeof(uint16_t))
     {
         return ;
     }
     packet_offset  = 0ul;
     while (packet_offset < (uint32_t)sz_unhashed)
     {
//          grab_sub_pkt_head (fp, &subpacket_size);          
          fread (&val, 1u, sizeof(uint8_t), fp);
          subpacket_size =  val;
          if (fread (grabbing, 1u, subpacket_size, fp) == subpacket_size)
          {
              if (*grabbing < 32)
              {
                  printf (sub_pkt_tag_txt[*grabbing]);
              }
              uh[2] = uh_index++;
              display_hex (uh, grabbing, subpacket_size); 
              packet_offset += subpacket_size + 1;
          }
     }
     return sz_unhashed + 2;
}

static void scan_open_pgp_file (int8_t *filename)
{
FILE *openPGPFile;
uint8_t good_read;
uint8_t pkt_tag;
uint8_t incomplete;
uint32_t expected_len;
enum packet_tags tagged;

uint8_t key_index=48u;
uint8_t sign_index=48u;
int8_t key[5]="key ";
int8_t sign[8]="sign ~ ";
int8_t keyname[8];
uint8_t algorithm=0u;
uint8_t val, i, n;
uint32_t len;

    good_read   = TRUE;
    openPGPFile = fopen (filename, "r+b");
    if (openPGPFile == 0L) return;

    mark_start (FALSE);
    while (!feof (openPGPFile) && good_read)
    {
        grab_packet_head (openPGPFile,
               &pkt_tag, &incomplete, &expected_len); 

        tagged = pkt_tag;
        if (tagged == PktSignature)
        {
            good_read = FALSE;
            algorithm = 0u;
            if (fread (grabbing, 1u, 1u, openPGPFile) == 1u)
            {
                if (grabbing[0] == 3u)
                {
                    if (fread (grabbing, 1u, 16u, openPGPFile) == 16u)
                    {
                        printf ("Signature Version 3\n");
                        printf ("type: %02x\n",        grabbing[1]); 
                        printf ("pub-key alg: %02x\n", grabbing[14]);
                        printf ("hash: %02x\n",        grabbing[15]);
                        algorithm = grabbing[14];
                        expected_len--;
                        expected_len -= 16u;
                        printf ("Block remaining:- %d\n", expected_len);
//                        if (fread (grabbing, 1u, expected_len, openPGPFile) ==
//                                expected_len) good_read = TRUE;
                        fread (grabbing, 1u, sizeof(uint16_t), openPGPFile);
                        good_read = TRUE;
                    }
                }
                else if (grabbing[0] == 4u)
                {
                    if (fread (grabbing, 1u, 3u, openPGPFile) == 3u)
                    {
                        printf ("Signature Version 4\n");
                        printf ("type: %02x\n",        grabbing[0]);
                        printf ("pub-key alg: %02x\n", grabbing[1]);
                        printf ("hash: %02x\n",        grabbing[2]);
                        algorithm = grabbing[1];
                        expected_len--;
                        expected_len -= 3u;
                        expected_len -= grab_hashed (openPGPFile);
                        expected_len -= grab_unhashed (openPGPFile);
                        printf ("Block remaining:- %d\n", expected_len);
//                        if (fread (grabbing, 1u, expected_len, openPGPFile) ==
//                                expected_len) good_read = TRUE;
                        fread (grabbing, 1u, sizeof(uint16_t), openPGPFile);
                        good_read = TRUE;
                    }
                }
                else if (grabbing[0] == 2u)
                {
                    expected_len--;
                    printf ("Block remaining: %d\n", expected_len);
                    if (fread (grabbing, 1u, expected_len, openPGPFile) ==
                            expected_len) good_read = TRUE;
                }
                if ((algorithm ==  1u) || (algorithm == 17u))
                {
                    fread (&val, 1u, 1u, openPGPFile);
                    expected_len   = (uint32_t)val;
                    expected_len <<= 8;
                    fread (&val, 1u, 1u, openPGPFile);
                    expected_len  += (uint32_t)val;
                    printf ("First MPI total bits:- %d\n", expected_len);
                    if (expected_len % 8) expected_len +=8;
                    expected_len /= 8;
                    if (fread (grabbing, 1u, expected_len, openPGPFile) ==
                            expected_len) good_read = TRUE;
                    display_hex ("first MPI ", grabbing, expected_len);
                }
                if (algorithm == 17u)
                {
                    fread (&val, 1u, 1u, openPGPFile);
                    expected_len   = (uint32_t)val;
                    expected_len <<= 8;
                    fread (&val, 1u, 1u, openPGPFile);
                    expected_len  += (uint32_t)val;
                    printf ("Second MPI total bits:- %d\n", expected_len);
                    if (expected_len % 8) expected_len +=8;
                    expected_len /= 8;
                    if (fread (grabbing, 1u, expected_len, openPGPFile) ==
                            expected_len) good_read = TRUE;
                    display_hex ("second MPI ", grabbing, expected_len);
                }
                    
            }
        }
        else
        {
            switch (tagged)
            {
               case PktPublicKey:
                    good_read = FALSE;
                    if (fread (grabbing, 1u, expected_len, openPGPFile) ==
                            expected_len)
                    {
                        if (buf_write (0u, grabbing, expected_len) ==
                                expected_len)
                        {
                            mark_end (FALSE);
                            good_read = TRUE;
                            key[3]=key_index++;
                            sign_index = 48u;
//                            display_hex (key, grabbing, expected_len);
                            display_hex ("Time: ", grabbing + 1, 4u);
                            if ((grabbing[0] == 3u) || (grabbing[0] == 2u))
                            {
                                printf ("Public Key Version %c\n", '0'+grabbing[0]);
                                display_hex ("Days valid: ", grabbing + 5, 2u);
                                display_hex ("Alg: ", grabbing + 7, 1u);
                                algorithm = grabbing[7];
                                val = 8;
                            }
                            else if (grabbing[0] == 4u)
                            {
                                printf ("Public Key Version 4\n");
                                display_hex ("Alg: ", grabbing + 5, 1u);
                                algorithm = grabbing[5];
                                val = 6;
                            }
                            len = (uint32_t)val;
                            switch (algorithm)
                            {
                                case 1u:
                                    n = 2;
                                    break;
                                case 17u:
                                    n = 4;
                                    break;
                                default:
                                    n = 0;
                                    break;
                            }

                            for (i = 0; i < n; i++)
                            {
                                expected_len = (grabbing[len]<<8) + grabbing[len+1];
                                printf ("%dth MPI total bits:- %d\n", i, expected_len);
                                if (expected_len % 8) expected_len +=8;
                                expected_len /= 8;
                                len += expected_len + 2;
                                display_hex ("--- MPI ", grabbing, expected_len);
                            }
                        }
                    }
                    break;
                case PktPKESKP:
                    if (fread (grabbing, 1u, 10u, openPGPFile) == 10u)
                    {
                        printf ("PUBLIC Encrypted Symmetric Key Packet Version %d\n", grabbing[0]);
                        display_hex ("ID: ", grabbing+1, 8u);
                        printf ("Symmetric Key Algorithm used: %d\n", grabbing[9]);
                        expected_len -= 10u;
                        if (fread (grabbing, 1u, expected_len, openPGPFile) ==
                                expected_len) good_read = TRUE;
                        display_hex ("ESKP: ", grabbing, expected_len);
                    }
                    break;
                case PktSKESKP:
                    if (fread (grabbing, 1u, 2u, openPGPFile) == 2u)
                    {
                        printf ("SYMMETRIC Encrypted Symmetric Key Packet Version %d\n", grabbing[0]);
                        printf ("Symmetric Key Algorithm used: %d\n", grabbing[1]);
                        expected_len -= 3u;
                        switch (grabbing[2])
                        {
                            case SimpleS2K:
                                if (fread (grabbing+1, 1u, 2u, openPGPFile) == 2u)
                                {
                                    printf ("Hash alg: %d\n", ((struct salted_s2k *)grabbing)->hash_algorithm);
                                    expected_len -= 2u;
                                }
                                break;
                            case SaltedS2K:
                                if (fread (grabbing+1, 1u, 10u, openPGPFile) == 10u)
                                {
                                    printf ("Hash alg: %d\n", ((struct salted_s2k *)grabbing)->hash_algorithm);
                                    display_hex ("Salt: ", ((struct salted_s2k *)grabbing)->salt, 8u);
                                    expected_len -= 10u;
                                }
                                break;
                            case IteratedSaltedS2K:
                                if (fread (grabbing+1, 1u, 11u, openPGPFile) == 11u)
                                {
                                    printf ("Hash alg: %d\n", ((struct salted_s2k *)grabbing)->hash_algorithm);
                                    display_hex ("Salt: ", ((struct salted_s2k *)grabbing)->salt, 8u);
                                    printf ("Count: %d\n", ((struct salted_s2k *)grabbing)->count);
                                    expected_len -= 11u;
                                }
                                break;
                            default:
                                break;
                        }                        
                        if (fread (grabbing, 1u, expected_len, openPGPFile) ==
                                expected_len) good_read = TRUE;
                        display_hex ("ESKP: ", grabbing, expected_len);
                    }
                    break;
                case PktSymEncIntegrityProtData:
                    printf ("Packet Sym Enc Integrity Prot Data - position 00\n");
                    fread (grabbing, 1u, 1u, openPGPFile);
                    expected_len--;
                case PktSymmetricEncData:
                    printf ("LENGTH: %ld\n", expected_len);
                    if (fread (grabbing, 1u, expected_len, openPGPFile) ==
                            expected_len) good_read = TRUE;
                    display_hex ("Sym Enc DATA: ", grabbing, expected_len);
                    break;
                case PktUserID:
                    good_read = FALSE;
                    if (fread (grabbing, 1u, expected_len, openPGPFile) ==
                            expected_len)
                    {
                        grabbing[expected_len] = '\0';
                        printf ("NAME:= %s\n", grabbing);
                        good_read = TRUE;
                    }
                    break;
                default:
                    good_read = FALSE;
                    if (fread (grabbing, 1u, expected_len, openPGPFile) ==
                            expected_len)
                    {
                        good_read = TRUE;
                    }
                    break;
            }
        }
    }
    fclose (openPGPFile);
}
 
extern int32_t main (uint8_t argc, int8_t *argv[])
{
    if (argc == 2)
    {
        scan_open_pgp_file (argv[1]);
    }
    else
    {
        return (1u);
    }
}

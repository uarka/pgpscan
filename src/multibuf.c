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

#define global
#define NUM_BUFS        (1u)
#define BUF_SIZE        (8192u)
#define FALSE           (0u)
#define TRUE            (!FALSE)

//static uint8_t   bufferFull[NUM_BUFS] = { FALSE, FALSE };
static uint8_t   bufferFull[NUM_BUFS] = { FALSE };
static uint8_t   Buffer[NUM_BUFS][BUF_SIZE + 1];
//global uint8_t  *pStart[NUM_BUFS] = { Buffer[0], Buffer[1] };
//global uint8_t  *pEnd[NUM_BUFS]   = { Buffer[0], Buffer[1] };
global uint8_t  *pStart[NUM_BUFS] = { Buffer[0] };
global uint8_t  *pEnd[NUM_BUFS]   = { Buffer[0] };


static uint8_t cyclic_check (const uint8_t *pBuffer, const uint8_t *pInitial, uint16_t size)
{
    size = (size > BUF_SIZE) ? BUF_SIZE : size; 
    return ( (pBuffer + BUF_SIZE - size) <= pInitial );
}

/***************************************************************************/
/*                                                                         */
/* check_write                                                             */
/* INPUTS: index - cyclic buffer used                                      */
/*         pBuf - pointer to write buffer                                  */
/*         size - size of write buffer                                     */
/* RETURN: new size of write buffer                                        */
/*                                                                         */
/* Perform a basic check to see whether we will pass the start pointer     */
/* whilst writing. Then do the memory copy from the write buffer to the    */
/* cyclic buffer. Finally return the actual number of bytes written        */
/*                                                                         */
/***************************************************************************/

static uint16_t check_write (uint8_t index, const uint8_t *pBuf, uint16_t size)
{
     if ( (pStart[index] > pEnd[index]) && (size > (pStart[index] - pEnd[index])) )
     {
         size = pStart[index] - pEnd[index];
     }
     memcpy (pEnd[index], pBuf, size);
     return (size);
}

/***************************************************************************/
/*                                                                         */
/* check_read                                                              */
/* INPUTS: index - cyclic buffer used                                      */
/*         pBuf - pointer to read buffer                                   */
/*         size - size of read buffer                                      */
/* RETURN: new size of read buffer                                         */
/*                                                                         */
/* Perform a basic check to see whether we will pass the end pointer       */
/* whilst reading. Then do the memory copy from the cyclic buffer to the   */
/* read buffer. Finally return the actual number of bytes read             */
/*                                                                         */
/***************************************************************************/

static uint16_t check_read (uint8_t index, uint8_t *pBuf, uint16_t size)
{
     if ( (pEnd[index] > pStart[index]) && (size > (pEnd[index] - pStart[index])) )
     {
         size = pEnd[index] - pStart[index];
     }
     memcpy (pBuf, pStart[index], size);
     return (size);
}

/***************************************************************************/
/*                                                                         */
/* buf_write                                                               */
/* INPUTS: index - cyclic buffer used                                      */
/*         pBuf - pointer to write buffer                                  */
/*         size - size of write buffer                                     */
/* RETURN: number of bytes written to cyclic buffer                        */
/*                                                                         */
/* First we check whether a write will cross the end of the cyclic buffer. */
/* If it does we process the write in two parts; Firstly we perform a      */
/* memory copy upto the end of the cyclic buffer, and subsequently we copy */
/* the remaining bytes from the start of the cyclic buffer, whilst         */
/* checking we do not pass the start pointer. Alternatively if there is no */
/* need to copy past the end of the cyclic buffer we copy the bytes,       */
/* whilst checking that we do not pass the start pointer.                  */
/*                                                                         */
/***************************************************************************/   

extern uint16_t buf_write (uint8_t index, const uint8_t *pBuf, uint16_t size)
{
uint16_t remainder;

    remainder = 0u;
    if (!bufferFull[index])
    {
        if (cyclic_check (Buffer[index], pEnd[index], size))
        {
            remainder = (Buffer[index] + BUF_SIZE - pEnd[index]);
            memcpy (pEnd[index], pBuf, remainder);
            pEnd[index]      = Buffer[index];
            if (pStart[index] == pEnd[index])
            {
                size  = 0u;
            }
            else
            { 
                size -= remainder;
                size  = check_write (index, pBuf + remainder, size);
            }
        }
        else
        {
            size = check_write (index, pBuf, size);
        }
        pEnd[index] += size;
        bufferFull[index] = (pStart[index] == pEnd[index]);
    }
    else
    {
        return (0u);
    }
    return (size + remainder);
}

/***************************************************************************/
/*                                                                         */
/* buf_read                                                                */
/* INPUTS: index - cyclic buffer used                                      */
/*         pBuf - pointer to read buffer                                   */
/*         size - size of read buffer                                      */
/* RETURN: number of bytes read from cyclic buffer                         */
/*                                                                         */
/* First we check whether a read will cross the end of the cyclic buffer.  */
/* If it does we process the read in two parts; Firstly we perform a       */
/* memory copy upto the end of the cyclic buffer, and subsequently we copy */
/* the remaining bytes from the start of the cyclic buffer, whilst         */
/* checking we do not pass the end pointer. Alternatively if there is no   */
/* need to copy past the end of the cyclic buffer we copy the bytes,       */
/* whilst checking that we do not pass the end pointer.                    */
/*                                                                         */
/***************************************************************************/   

extern uint16_t buf_read (uint8_t index, uint8_t *pBuf, uint16_t size)
{
uint16_t remainder;

    remainder = 0u;
    if ( (bufferFull[index] || (pStart[index] != pEnd[index])) && size )
    { 
        if (cyclic_check (Buffer[index], pStart[index], size))
        {
            remainder = (Buffer[index] + BUF_SIZE - pStart[index]);
            memcpy (pBuf, pStart[index], remainder);
            pStart[index]    = Buffer[index];
            if (pStart[index] == pEnd[index])
            {
                size  = 0u;
            }
            else
            {
                size -= remainder;
                size  = check_read (index, pBuf + remainder, size);
            }
        }
        else
        {
            size = check_read (index, pBuf, size);
        }
        pStart[index] += size;
        bufferFull[index] = FALSE;
    }
    else
    {
         return (0u);
    }
    return (size + remainder);
}

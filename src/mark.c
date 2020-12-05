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

#define NUM_MARKERS                     (4u)

#define SUCCESS                         (0u)
#define ERR_MARK_START_INSERTION        (1u)
#define ERR_MARK_END_INSERTION          (2u)
#define ERR_MARK_OTHER_INSERTION        (3u)

/* If using multibufs these need to be declared as such */

extern uint8_t  *pStart[];
extern uint8_t  *pEnd[];

/*
extern uint8_t  *pStart;
extern uint8_t  *pEnd;
*/
static uint8_t  *Marker   [NUM_MARKERS];
static uint8_t   SubMarker[NUM_MARKERS];
static uint8_t   total_markers = 0u;


/***************************************************************************/
/*                                                                         */
/* mark_start                                                              */
/* INPUTS: flag - indicating sub-packet                                    */
/* RETURN: success or failure (non-zero)                                   */
/*                                                                         */
/* Add the buffer start position to the marker stack                       */
/*                                                                         */
/***************************************************************************/

extern uint8_t mark_start (uint8_t flag)
{
    if (total_markers < NUM_MARKERS)
    {
        SubMarker [total_markers] = flag;
/*        Marker [total_markers++]  = pStart; */
        Marker [total_markers++]  = pStart[0];
        return SUCCESS;
    }

    return ERR_MARK_START_INSERTION;
}

/***************************************************************************/
/*                                                                         */
/* mark_end                                                                */
/* INPUTS: flag - indicating sub-packet                                    */
/* RETURN: success or failure (non-zero)                                   */
/*                                                                         */
/* Add the buffer end position to the marker stack                         */
/*                                                                         */
/***************************************************************************/

extern uint8_t mark_end (uint8_t flag)
{
    if (total_markers < NUM_MARKERS)
    {
        SubMarker[total_markers] = flag;
/*        Marker[total_markers++]  = pEnd; */
        Marker[total_markers++]  = pEnd[0];
        return SUCCESS;
    }

    return ERR_MARK_END_INSERTION;
}

/***************************************************************************/
/*                                                                         */
/* mark_buffer                                                             */
/* INPUTS: flag - indicating sub-packet                                    */
/*         pMark - pointer to the marker                                   */
/* RETURN: success or failure (non-zero)                                   */
/*                                                                         */
/* Add a new mark to the marker stack                                      */
/*                                                                         */
/***************************************************************************/

extern uint8_t mark_buffer (uint8_t flag, uint8_t *pMark)
{
    if (total_markers < NUM_MARKERS)
    {
        SubMarker[total_markers] = flag;
        Marker[total_markers++]  = pMark;
        return SUCCESS;
    }

    return ERR_MARK_OTHER_INSERTION;
}

/***************************************************************************/
/*                                                                         */
/* retrieve_marker                                                         */
/* INPUTS: index - offset into the stack of marker                          */
/* RETURN: pointer to the marker, or NULL if failed                        */
/*         pFlag - pointer to the sub-packet flag                          */
/*                                                                         */
/* Retreives the index element of the marker stack                         */
/*                                                                         */
/***************************************************************************/

extern uint8_t *retrieve_marker (uint8_t index, uint8_t *pFlag)
{
    if (index < total_markers)
    {
        *pFlag = SubMarker[index];
        return Marker[index];
    }
    return NULL;
}

/***************************************************************************/
/*                                                                         */
/* pop_marker                                                              */
/* INPUTS: none                                                            */
/* RETURN: pointer to the last marker, or NULL if failed                   */
/*         pFlag - pointer to the sub-packet flag                          */
/*                                                                         */
/* Retreives the last marker of the marker stack.                          */
/* NB a single instance marker will NOT be popped                          */
/*                                                                         */
/***************************************************************************/

extern uint8_t *pop_marker (uint8_t *pFlag)
{
    if (total_markers)
    {
        *pFlag = SubMarker[total_markers];
        return Marker[total_markers--];
    }
    else
    {
        *pFlag = SubMarker[0];
        return Marker[0];
    }
}

/***************************************************************************/
/*                                                                         */
/* last_marker                                                             */
/* INPUTS: none                                                            */
/* RETURN: pointer to the last marker, or NULL if failed                   */
/*         pFlag - pointer to the sub-packet flag                          */
/*                                                                         */
/* Retreives the last marker of the marker stack.                          */
/* NB a single instance marker will NOT be popped                          */
/*                                                                         */
/***************************************************************************/

extern uint8_t *last_marker (uint8_t *pFlag)
{
    *pFlag = SubMarker[total_markers];
    return Marker[total_markers];
}

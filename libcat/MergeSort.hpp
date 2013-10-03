/*
	Copyright (c) 2011 Christopher A. Taylor.  All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.
	* Neither the name of LibCat nor the names of its contributors may be used
	  to endorse or promote products derived from this software without
	  specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
	ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef CAT_MERGE_SORT_HPP
#define CAT_MERGE_SORT_HPP

#include <cat/Platform.hpp>
#include <cat/io/Log.hpp>

/*
	I took the time to write an optimized Merge Sort for singly-linked lists
	so decided to make it templated and reusable.  It takes about 30% less
	time on average than a naive implementation of mergesort.
*/

namespace cat {


template<class BaseType, typename CompareType>
class SortableItem
{
	// Skip list used for faster sorting of the modified list
	BaseType *_sort_skip;

protected:
	// Next item in list to be sorted
	BaseType *_sort_next;

	// Value to use for comparison
	CompareType _sort_value;

public:
	// Sort a list with merge sort
	static BaseType *MergeSort(BaseType *head);
};


/*
	MergeSort for a singly-linked list

	Why?  This version takes roughly 2/3rds the time of a naive implementation

	Preserves existing order for items that have the same position
*/
template<class BaseType, typename CompareType>
BaseType *SortableItem<BaseType, CompareType>::MergeSort(BaseType *head)
{
	if (!head) return 0;

	// Unroll first loop where consecutive pairs are put in order
	BaseType *a = head, *tail = 0, *skip_last = 0;
	do
	{
		// Grab second item in pair
		BaseType *b = a->_sort_next;

		// If no second item in pair,
		if (!b)
		{
			// Initialize the skip pointer to null
			a->_sort_skip = 0;

			// Done with this step size!
			break;
		}

		// Remember next pair in case swap occurs
		BaseType *next_pair = b->_sort_next;

		// If current pair are already in order,
		if (a->_sort_value <= b->_sort_value)
		{
			// Remember b as previous node
			tail = b;

			// Maintain skip list for next pass
			skip_last = a;
		}
		else // pair is out of order
		{
			// Fix a, b next pointers
			a->_sort_next = next_pair;
			b->_sort_next = a;

			// Link b to previous node
			if (tail)
			{
				tail->_sort_next = b;

				// Fix skip list from last pass
				CAT_DEBUG_ENFORCE(skip_last);
				skip_last->_sort_skip = b;
			}
			else head = b;

			// Remember a as previous node
			tail = a;

			// Maintain skip list for next pass
			skip_last = b;
		}

		skip_last->_sort_skip = next_pair;

		// Continue at next pair
		a = next_pair;
	} while (a);

	// Continue from step size of 2
	int step_size = 2;
	CAT_FOREVER
	{
		// Unroll first list merge for exit condition
		a = head;
		tail = 0;

		// Grab start of second list
		BaseType *b = a->_sort_skip;

		// If no second list, sorting is done
		if (!b) break;

		// Remember pointer to next list
		BaseType *next_list = b->_sort_skip;

		// Cache a, b offsets
		u32 aoff = a->_sort_value, boff = b->_sort_value;

		// Merge two lists together until step size is exceeded
		int b_remaining = step_size;
		BaseType *b_head = b;
		CAT_FOREVER
		{
			// In cases where both are equal, preserve order
			if (aoff <= boff)
			{
				// Set a as tail
				if (tail) tail->_sort_next = a;
				else head = a;
				tail = a;

				// Grab next a
				a = a->_sort_next;

				// If ran out of a-items,
				if (a == b_head)
				{
					// Link remainder of b-items to the end
					tail->_sort_next = b;

					// Fix tail pointer
					while (--b_remaining > 0)
					{
						BaseType *next = b->_sort_next;
						if (!next) break;
						b = next;
					}
					tail = b;

					// Done with this step size
					break;
				}

				// Update cache of a-offset
				aoff = a->_sort_value;
			}
			else
			{
				// Set b as tail
				if (tail) tail->_sort_next = b;
				else head = b;
				tail = b;

				// Grab next b
				b = b->_sort_next;

				// If ran out of b-items,
				if (--b_remaining == 0 || !b)
				{
					// Link remainder of a-items to end
					tail->_sort_next = a;

					// Need to fix the final next pointer of the appended a-items
					BaseType *prev;
					do
					{
						prev = a;
						a = a->_sort_next;
					} while (a != b_head);
					prev->_sort_next = b;
					tail = prev;

					// Done with this step size
					break;
				}

				// Update cache of b-offset
				boff = b->_sort_value;
			}
		}

		// Remember start of merged list for fixing the skip list later
		skip_last = head;

		// Second and following merges
		while ((a = next_list))
		{
			// Grab start of second list
			b = a->_sort_skip;

			// If no second list, done with this step size
			if (!b)
			{
				// Fix skip list
				skip_last->_sort_skip = a;

				break;
			}

			// Remember pointer to next list
			next_list = b->_sort_skip;

			// Remember previous tail for fixing the skip list later
			BaseType *prev_tail = tail;

			// First item in the new list will be either a or b
			// b already has next list pointer set, so just update a
			a->_sort_skip = next_list;

			// Cache a, b offsets
			aoff = a->_sort_value;
			boff = b->_sort_value;

			// Merge two lists together until step size is exceeded
			b_remaining = step_size;
			b_head = b;
			CAT_FOREVER
			{
				// In cases where both are equal, preserve order
				if (aoff <= boff)
				{
					// Set a as tail
					tail->_sort_next = a;
					tail = a;

					// Grab next a
					a = a->_sort_next;

					// If ran out of a-items,
					if (a == b_head)
					{
						// Link remainder of b-items to the end
						tail->_sort_next = b;

						// Fix tail pointer
						while (--b_remaining > 0)
						{
							BaseType *next = b->_sort_next;
							if (!next) break;
							b = next;
						}
						tail = b;

						// Done with this step size
						break;
					}

					// Update cache of a-offset
					aoff = a->_sort_value;
				}
				else
				{
					// Set b as tail
					tail->_sort_next = b;
					tail = b;

					// Grab next b
					b = b->_sort_next;

					// If ran out of b-items,
					if (--b_remaining == 0 || !b)
					{
						// Link remainder of a-items to end
						tail->_sort_next = a;

						// Need to fix the final next pointer of the appended a-items
						BaseType *prev;
						do
						{
							prev = a;
							a = a->_sort_next;
						} while (a != b_head);
						prev->_sort_next = b;
						tail = prev;

						// Done with this step size
						break;
					}

					// Update cache of b-offset
					boff = b->_sort_value;
				}
			}

			// Determine segment head and fix skip list
			BaseType *seg_head = prev_tail->_sort_next;
			skip_last->_sort_skip = seg_head;
			skip_last = seg_head;
		}

		// Fix final skip list pointer
		skip_last->_sort_skip = next_list;

		// Double step size
		step_size *= 2;
	}

	return head;
}


} // namespace cat

#endif // CAT_MERGE_SORT_HPP

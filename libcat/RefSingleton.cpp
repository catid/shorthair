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

#include <cat/lang/RefSingleton.hpp>
#include <cat/threads/Thread.hpp>
using namespace cat;

static RefSingletons *m_ref_singletons = 0;



//// Mutex

static Mutex m_ref_singleton_mutex;

Mutex &cat::GetRefSingletonMutex()
{
	return m_ref_singleton_mutex;
}


//// RefSingletonBase

void RefSingletonBase::MergeSort(SListForward &list)
{
	if (list.Empty()) return;

	RefSingletonBase *head = static_cast<RefSingletonBase*>( list.Head() );

	// Unroll first loop where consecutive pairs are put in order
	RefSingletonBase *a = head, *tail = 0, *skip_last = 0;
	do
	{
		// Grab second item in pair
		RefSingletonBase *b = static_cast<RefSingletonBase*>( a->_sl_next );

		// If no second item in pair,
		if (!b)
		{
			// Initialize the skip pointer to null
			a->_skip_next = 0;

			// Done with this step size!
			break;
		}

		// Remember next pair in case swap occurs
		RefSingletonBase *next_pair = static_cast<RefSingletonBase*>( b->_sl_next );

		// If current pair are already in order,
		if (a->_final_priority <= b->_final_priority)
		{
			// Remember b as previous node
			tail = b;

			// Maintain skip list for next pass
			skip_last = a;
		}
		else // pair is out of order
		{
			// Fix a, b next pointers
			a->_sl_next = next_pair;
			b->_sl_next = a;

			// Link b to previous node
			if (tail)
			{
				tail->_sl_next = b;

				// Fix skip list from last pass
				CAT_DEBUG_ENFORCE(skip_last);
				skip_last->_skip_next = b;
			}
			else head = b;

			// Remember a as previous node
			tail = a;

			// Maintain skip list for next pass
			skip_last = b;
		}

		skip_last->_skip_next = next_pair;

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
		RefSingletonBase *b = a->_skip_next;

		// If no second list, sorting is done
		if (!b) break;

		// Remember pointer to next list
		RefSingletonBase *next_list = b->_skip_next;

		// Cache a, b offsets
		u32 aoff = a->_final_priority, boff = b->_final_priority;

		// Merge two lists together until step size is exceeded
		int b_remaining = step_size;
		RefSingletonBase *b_head = b;
		CAT_FOREVER
		{
			// In cases where both are equal, preserve order
			if (aoff <= boff)
			{
				// Set a as tail
				if (tail) tail->_sl_next = a;
				else head = a;
				tail = a;

				// Grab next a
				a = static_cast<RefSingletonBase*>( a->_sl_next );

				// If ran out of a-items,
				if (a == b_head)
				{
					// Link remainder of b-items to the end
					tail->_sl_next = b;

					// Fix tail pointer
					while (--b_remaining > 0)
					{
						RefSingletonBase *next = static_cast<RefSingletonBase*>( b->_sl_next );
						if (!next) break;
						b = next;
					}
					tail = b;

					// Done with this step size
					break;
				}

				// Update cache of a-offset
				aoff = a->_final_priority;
			}
			else
			{
				// Set b as tail
				if (tail) tail->_sl_next = b;
				else head = b;
				tail = b;

				// Grab next b
				b = static_cast<RefSingletonBase*>( b->_sl_next );

				// If ran out of b-items,
				if (--b_remaining == 0 || !b)
				{
					// Link remainder of a-items to end
					tail->_sl_next = a;

					// Need to fix the final next pointer of the appended a-items
					RefSingletonBase *prev;
					do
					{
						prev = a;
						a = static_cast<RefSingletonBase*>( a->_sl_next );
					} while (a != b_head);
					prev->_sl_next = b;
					tail = prev;

					// Done with this step size
					break;
				}

				// Update cache of b-offset
				boff = b->_final_priority;
			}
		}

		// Remember start of merged list for fixing the skip list later
		skip_last = head;

		// Second and following merges
		while ((a = next_list))
		{
			// Grab start of second list
			b = a->_skip_next;

			// If no second list, done with this step size
			if (!b)
			{
				// Fix skip list
				skip_last->_skip_next = a;

				break;
			}

			// Remember pointer to next list
			next_list = b->_skip_next;

			// Remember previous tail for fixing the skip list later
			RefSingletonBase *prev_tail = tail;

			// First item in the new list will be either a or b
			// b already has next list pointer set, so just update a
			a->_skip_next = next_list;

			// Cache a, b offsets
			aoff = a->_final_priority;
			boff = b->_final_priority;

			// Merge two lists together until step size is exceeded
			b_remaining = step_size;
			b_head = b;
			CAT_FOREVER
			{
				// In cases where both are equal, preserve order
				if (aoff <= boff)
				{
					// Set a as tail
					tail->_sl_next = a;
					tail = a;

					// Grab next a
					a = static_cast<RefSingletonBase*>( a->_sl_next );

					// If ran out of a-items,
					if (a == b_head)
					{
						// Link remainder of b-items to the end
						tail->_sl_next = b;

						// Fix tail pointer
						while (--b_remaining > 0)
						{
							RefSingletonBase *next = static_cast<RefSingletonBase*>( b->_sl_next );
							if (!next) break;
							b = next;
						}
						tail = b;

						// Done with this step size
						break;
					}

					// Update cache of a-offset
					aoff = a->_final_priority;
				}
				else
				{
					// Set b as tail
					tail->_sl_next = b;
					tail = b;

					// Grab next b
					b = static_cast<RefSingletonBase*>( b->_sl_next );

					// If ran out of b-items,
					if (--b_remaining == 0 || !b)
					{
						// Link remainder of a-items to end
						tail->_sl_next = a;

						// Need to fix the final next pointer of the appended a-items
						RefSingletonBase *prev;
						do
						{
							prev = a;
							a = static_cast<RefSingletonBase*>( a->_sl_next );
						} while (a != b_head);
						prev->_sl_next = b;
						tail = prev;

						// Done with this step size
						break;
					}

					// Update cache of b-offset
					boff = b->_final_priority;
				}
			}

			// Determine segment head and fix skip list
			RefSingletonBase *seg_head = static_cast<RefSingletonBase*>( prev_tail->_sl_next );
			skip_last->_skip_next = seg_head;
			skip_last = seg_head;
		}

		// Fix final skip list pointer
		skip_last->_skip_next = next_list;

		// Double step size
		step_size *= 2;
	}

	list = head;
}


//// RefSingletons

void RefSingletons::AtExit()
{
	if (m_ref_singletons)
	{
		m_ref_singletons->OnFinalize();
		m_ref_singletons = 0;
	}

	CAT_DEBUG_LEAKS_DUMP();
}

CAT_SINGLETON(RefSingletons);

bool RefSingletons::OnInitialize()
{
	CAT_DEBUG_MEM_FLAGS();

	m_ref_singletons = this;

	std::atexit(&RefSingletons::AtExit);

	return true;
}

void RefSingletons::OnFinalize()
{
	// Bin-sort active singletons
	static const int BIN_COUNT = 16;
	SListForward bins[BIN_COUNT];
	SListForward dregs;

	// For each active singleton,
	for (iter ii = _active_list; ii; ++ii)
	{
		u32 prio = ii->_final_priority;
		if (prio < BIN_COUNT)
			bins[prio].PushFront(ii);
		else
			dregs.PushFront(ii);
	}

	// Sort remainder list
	RefSingletonBase::MergeSort(dregs);

	// For each bin in order,
	for (int prio = 0; prio < BIN_COUNT; ++prio)
	{
		// For each active singleton in the bin,
		for (iter ii = bins[prio]; ii; ++ii)
		{
			ii->OnFinalize();
		}
	}

	// For each remaining singleton,
	for (iter ii = dregs; ii; ++ii)
	{
		ii->OnFinalize();
	}

	// NOTE: No need to clear the list since it is not accessed after this point
	//_active_list.Clear();
}

/*
 * Copyright 2019 Jeremy Jamet / Kunzisoft.
 *
 * This file is part of KeePassDX.
 *
 *  KeePassDX is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  KeePassDX is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with KeePassDX.  If not, see <http://www.gnu.org/licenses/>.
 *
 * TDD driving tests for the cache-invalidation audit (Bug #6): the UI save
 * path runs DatabaseInfo.updateEntry(entry, entryInfo) -> Entry.saveEntryInfo,
 * which mutates the indexed EntryKDBX in place WITHOUT clearing the
 * reference cache. Index replacement + cache clear only happen later, in
 * Database.updateEntry(entry) (UpdateEntryRunnable.nodeAction). Decodes in
 * between serve stale reference values.
 */
package com.kunzisoft.keepass.tests.element.entry

import com.kunzisoft.keepass.database.element.Entry
import com.kunzisoft.keepass.database.element.entry.EntryKDBX
import com.kunzisoft.keepass.database.element.node.NodeIdUUID
import com.kunzisoft.keepass.model.DatabaseInfo
import com.kunzisoft.keepass.model.EntryInfo
import com.kunzisoft.keepass.utils.UUIDUtils.asHexCharArray
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class FieldReferencesCacheInvalidationTest {

    private lateinit var mDatabaseInfo: DatabaseInfo

    private lateinit var mEntryB: Entry

    private lateinit var mEntryA: Entry

    @Before
    fun setUp() {
        mDatabaseInfo = DatabaseInfo().apply {
            createData("CacheInvalidationDB", "Root", null)
        }
        val hexB = String(NodeIdUUIDFor("B").id.asHexCharArray()!!)
        mEntryB = newEntry("B", "Target", "oldUser")
        mDatabaseInfo.addEntryTo(mEntryB, mDatabaseInfo.rootGroup!!)
        mEntryA = newEntry("A", "Source", "{REF:U@I:$hexB}")
        mDatabaseInfo.addEntryTo(mEntryA, mDatabaseInfo.rootGroup!!)
    }

    private fun NodeIdUUIDFor(suffix: String) =
        com.kunzisoft.keepass.database.element.node.NodeIdUUID(
            UUID.fromString("00000000-0000-0000-0000-${suffix.padStart(12, '0')}"))

    /** Simplified builder: an EntryKDBX with fields set and a stable id. */
    private fun newEntry(idHexSuffix: String, title: String, username: String): Entry {
        val kdbx = EntryKDBX().apply {
            this.title = title
            this.username = username
            nodeId = NodeIdUUIDFor(idHexSuffix)
        }
        return Entry(kdbx)
    }

    private fun decodedUsername(): String =
        mDatabaseInfo.getEntryById(mEntryA.nodeId)!!
            .let { mDatabaseInfo.getEntryInfoFrom(it) }
            .username

    // The exact UI sequence: decode A (populates the cache), then save a new
    // EntryInfo for B through the two-argument path (in-place mutation, no
    // cache clear), then decode again — must not serve the stale cached
    // reference value.
    @Test
    fun inPlaceSaveDoesNotServeStaleReferences() {
        assertEquals("oldUser", decodedUsername())

        val bEntry = mDatabaseInfo.getEntryById(mEntryB.nodeId)!!
        val newInfo = EntryInfo().apply {
            nodeId = bEntry.nodeId
            title = "Target"
            username = "newUser"
        }
        // DatabaseInfo.updateEntry -> saveEntryInfo (in place, no clear)
        mDatabaseInfo.updateEntry(bEntry, newInfo)

        assertEquals("stale cached reference after in-place save", "newUser", decodedUsername())
    }
}
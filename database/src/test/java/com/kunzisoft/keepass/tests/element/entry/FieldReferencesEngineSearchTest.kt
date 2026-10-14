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
 * TDD driving tests for Bug #3 (raw search): {REF:...@T/@U/@P/@A/@N}
 * lookups compare candidates' RAW stored fields against the search query.
 * A candidate whose searched field is itself a placeholder can never be
 * found, and the reference resolves to nothing.
 */
package com.kunzisoft.keepass.tests.element.entry

import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import com.kunzisoft.keepass.database.element.entry.EntryKDBX
import com.kunzisoft.keepass.database.element.node.NodeIdUUID
import com.kunzisoft.keepass.database.element.security.ProtectedString
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
class FieldReferencesEngineSearchTest {

    private lateinit var mDatabase: DatabaseKDBX

    @Before
    fun setUp() {
        mDatabase = DatabaseKDBX("SearchTestDB", "Root")
    }

    private fun addEntry(
        uuidHexSuffix: String,
        title: String = "",
        username: String = "",
        vararg customFields: Pair<String, String>
    ): EntryKDBX {
        val uuid = UUID.fromString("00000000-0000-0000-0000-${uuidHexSuffix.padStart(12, '0')}")
        val entry = EntryKDBX().apply {
            this.title = title
            this.username = username
            customFields.forEach { (name, value) ->
                putField(name, ProtectedString(false, value))
            }
            nodeId = NodeIdUUID(uuid)
        }
        mDatabase.addEntryTo(entry, mDatabase.rootGroup!!)
        return entry
    }

    /** {REF:...@I:...} accepts the KeePass raw-byte hex form of a UUID. */
    private fun refHex(entry: EntryKDBX): String = String(entry.nodeId.id.asHexCharArray()!!)

    private fun decodeManagedField(entry: EntryKDBX, label: String): String {
        entry.startToManageFieldReferences(mDatabase)
        try {
            val raw = entry.getFieldValue(label)!!.charArrayValue
            return String(mDatabase.getFieldReferenceValue(entry, raw, 0))
        } finally {
            entry.stopToManageFieldReferences()
        }
    }

    // Search target found by title where the candidate's title field is
    // itself a {S:} placeholder resolving to the searched value.
    @Test
    fun refByTitleMatchesCandidateWithSPlaceholderTitle() {
        addEntry(
            "EE",
            title = "{S:label}", username = "userE",
            "label" to "ComputedTitle")
        val f = addEntry(
            "FF",
            title = "Source3", username = "{REF:U@T:ComputedTitle}")
        assertEquals("userE", decodeManagedField(f, "UserName"))
    }

    // Search target found by title where the candidate's title field is
    // itself a {REF:} to a third entry carrying the literal title.
    @Test
    fun refByTitleMatchesCandidateWithRefTitle() {
        val literal = addEntry(
            "11",
            title = "DisplayName", username = "userX")
        addEntry(
            "22",
            title = "{REF:T@I:${refHex(literal)}} v2", username = "userY")
        val f = addEntry(
            "33",
            title = "Source3", username = "{REF:U@T:DisplayName v2}")
        assertEquals("userY", decodeManagedField(f, "UserName"))
    }
}
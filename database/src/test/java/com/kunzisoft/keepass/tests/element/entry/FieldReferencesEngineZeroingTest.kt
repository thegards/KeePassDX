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
 * TDD driving tests for Bug #2 (zeroing corruption): any engine loop
 * iteration whose cache pass is a no-op zeroes the working text, so
 * fields containing more than one placeholder (or a placeholder that
 * only appears mid-loop) resolve to NUL-filled output.
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
class FieldReferencesEngineZeroingTest {

    private lateinit var mDatabase: DatabaseKDBX

    @Before
    fun setUp() {
        mDatabase = DatabaseKDBX("ZeroingTestDB", "Root")
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

    private fun decodeManagedTitle(entry: EntryKDBX): String {
        entry.startToManageFieldReferences(mDatabase)
        try {
            return String(entry.decodeTitleKey(0))
        } finally {
            entry.stopToManageFieldReferences()
        }
    }

    private fun decodeManagedField(entry: EntryKDBX, label: String): String {
        entry.startToManageFieldReferences(mDatabase)
        try {
            val raw = entry.getFieldValue(label)!!.charArrayValue
            return String(mDatabase.getFieldReferenceValue(entry, raw, 0))
        } finally {
            entry.stopToManageFieldReferences()
        }
    }

    // Zeroing case A: two {S:} placeholders in one field.
    // Current master returns 17 NUL chars instead of "AA middle BB".
    @Test
    fun twoSelfReferencesInOneField() {
        val entry = addEntry(
            "AA",
            "{S:one} middle {S:two}",
            "",
            "one" to "AA",
            "two" to "BB")
        assertEquals("AA middle BB", decodeManagedTitle(entry))
    }

    // Zeroing case B: {S:} placeholder first, then {REF:}.
    // Current master zeroes the text in the iteration that follows the {S:}
    // resolution, because the {REF:} pass is a no-op at that point.
    @Test
    fun mixedSelfThenRef() {
        val target = addEntry(
            "BB",
            title = "TargetB", username = "userB")
        val entry = addEntry(
            "CC",
            "Source", "{S:prefix} to {REF:U@I:${refHex(target)}}",
            "prefix" to "user")
        assertEquals("user to userB", decodeManagedField(entry, "UserName"))
    }

    // Zeroing case C: {REF:} first, then {S:} — the leaked ordering.
    // Current master zeroes the text in the iteration that follows the
    // {REF:} resolution, because the {S:} pass is a no-op at that point.
    @Test
    fun mixedRefThenSelf() {
        val target = addEntry(
            "DD",
            title = "TargetD", username = "userD")
        val entry = addEntry(
            "EE",
            "Source", "{REF:U@I:${refHex(target)}} by {S:suffix}",
            "suffix" to "admin")
        assertEquals("userD by admin", decodeManagedField(entry, "UserName"))
    }
}
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
 * TDD driving tests for Bug #1 (transitive context): when the wanted field
 * of a {REF:...} target contains placeholders ({S:...} or {REF:...}), they
 * must be resolved in the context of the TARGET entry, not the referencing
 * entry. Target entries are never managed (mDecodeRef=false), so the engine
 * currently returns their raw field content; the leaked placeholder is then
 * re-resolved against the referencing entry.
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
class FieldReferencesEngineTransitiveTest {

    private lateinit var mDatabase: DatabaseKDBX

    @Before
    fun setUp() {
        mDatabase = DatabaseKDBX("TransitiveTestDB", "Root")
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

    // Transitive case A: target's {S:} references a custom field that ALSO
    // exists (with different content) on the referencing entry. The leaked
    // placeholder currently resolves against the referencing entry -> wrong
    // content instead of the target's value.
    @Test
    fun transitiveSResolvesInTargetContext() {
        val target = addEntry(
            "BB",
            title = "Target", username = "{S:domain}",
            "domain" to "target.example.org")
        val source = addEntry(
            "AA",
            title = "Source", username = "{REF:U@I:${refHex(target)}}",
            "domain" to "WRONG-ENTRY-DOMAIN")
        assertEquals("target.example.org", decodeManagedField(source, "UserName"))
    }

    // Transitive case B: same shape but the referencing entry has NO matching
    // custom field: leaked placeholder currently resolves to empty.
    @Test
    fun transitiveSWithMissingFieldOnReferencingEntry() {
        val target = addEntry(
            "CC",
            title = "Target2", username = "{S:domain}",
            "domain" to "target2.example.org")
        val source = addEntry(
            "DD",
            title = "Source2", username = "{REF:U@I:${refHex(target)}}")
        assertEquals("target2.example.org", decodeManagedField(source, "UserName"))
    }

    // Transitive case C: nested REF chain A -> B -> C; C's username contains
    // an {S:} that must resolve against C.
    @Test
    fun nestedRefChainResolvesEachLinkInItsOwnContext() {
        val c = addEntry(
            "EE",
            title = "EntryC", username = "{S:origin}",
            "origin" to "c.example.org")
        val b = addEntry(
            "FF",
            title = "EntryB", username = "{REF:U@I:${refHex(c)}}")
        val a = addEntry(
            "00",
            title = "EntryA", username = "{REF:U@I:${refHex(b)}}")
        assertEquals("c.example.org", decodeManagedField(a, "UserName"))
    }
}
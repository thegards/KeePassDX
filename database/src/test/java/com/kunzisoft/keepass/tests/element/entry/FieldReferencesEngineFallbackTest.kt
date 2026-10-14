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
 * TDD driving tests for Bug #4 (fallback policy): when resolution cannot
 * complete (missing target, missing field, placeholder cycle, recursion
 * cap), the engine currently yields an EMPTY value or a hole in the text.
 * Agreed policy: leave the unresolved raw placeholder visible.
 */
package com.kunzisoft.keepass.tests.element.entry

import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import com.kunzisoft.keepass.database.element.entry.EntryKDBX
import com.kunzisoft.keepass.database.element.node.NodeIdUUID
import com.kunzisoft.keepass.database.element.security.ProtectedString
import com.kunzisoft.keepass.utils.UUIDUtils.asHexCharArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class FieldReferencesEngineFallbackTest {

    private lateinit var mDatabase: DatabaseKDBX

    @Before
    fun setUp() {
        mDatabase = DatabaseKDBX("FallbackTestDB", "Root")
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

    /** Zeroed tail (NULs) the current engine produces on failed resolution. */
    private fun hasTrailingNuls(s: String): Boolean = s.startsWith('{') && s.endsWith(0.toChar().toString())

    // Missing target: the reference points at a UUID that is not in the
    // database. Expect the placeholder to stay visible, not a hole.
    @Test
    fun missingTargetKeepsRawPlaceholder() {
        val entry = addEntry(
            "AA",
            title = "Source", username = "{REF:U@I:00000000000000000000000000000000} suffix")
        val decoded = decodeManagedField(entry, "UserName")
        assertFalse("no NUL hole expected", hasTrailingNuls(decoded))
        assertTrue("raw placeholder expected, got [$decoded]", decoded.contains("{REF:U@I:"))
    }

    // Missing field on the SELF entry: {S:missing} has no backing custom
    // field. Expect the placeholder to stay visible.
    @Test
    fun missingSelfFieldKeepsRawPlaceholder() {
        val entry = addEntry(
            "BB", title = "Source", username = "login: {S:missing}")
        val decoded = decodeManagedField(entry, "UserName")
        assertEquals("login: {S:missing}", decoded)
    }

    // Placeholder cycle between two entries referencing each other by title.
    // Expect a bounded resolution leaving a raw placeholder visible instead
    // of a stack overflow or an empty value.
    @Test
    fun placeholderCycleLeavesRawPlaceholder() {
        val a = addEntry(
            "01",
            title = "placeholder")
        val b = addEntry(
            "02",
            title = "placeholder")
        // Close the cycle by stored content: a searches b, b searches a
        b.title = "{REF:T@I:${refHex(a)}}"
        a.title = "{REF:T@I:${refHex(b)}}"
        val decoded = try {
            decodeManagedField(a, "Title")
        } catch (t: StackOverflowError) {
            "StackOverflowError"
        }
        assertTrue("cycle must not overflow, got [$decoded]", decoded != "StackOverflowError")
        assertTrue("raw placeholder expected, got [$decoded]", decoded.contains("{REF:"))
    }

    // Chain longer than the inline cap: expect resolved prefix and raw
    // placeholder tail, never zeros.
    @Test
    fun depthExhaustionKeepsRawPlaceholder() {
        // 12 {S:} placeholders, inline cap is 10
        val references = (1..12).joinToString(" ") { "{S:f$it}" }
        val entry = addEntry("03", title = "placeholder")
        // Overwrite title with the long placeholder chain
        entry.title = references
        (1..12).forEach { entry.putField("f$it", ProtectedString(false, "v$it")) }
        val decoded = decodeManagedField(entry, "Title")
        assertFalse("no zeros expected, got [${decoded.replace(0.toChar(), ' ')}]", decoded.any { it.code == 0 })
        assertEquals("got [$decoded]",
            "v1 v2 v3 v4 v5 v6 v7 v8 v9 v10 v11 {S:f12}", decoded)
    }
}
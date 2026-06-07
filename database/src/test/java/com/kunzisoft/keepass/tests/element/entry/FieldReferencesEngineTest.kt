/*
 * Copyright 2026 Jeremy Jamet / Kunzisoft.
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
 */
package com.kunzisoft.keepass.tests.element.entry

import android.os.Parcel
import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import com.kunzisoft.keepass.database.element.entry.EntryKDBX
import com.kunzisoft.keepass.database.element.group.GroupKDBX
import com.kunzisoft.keepass.database.element.node.NodeIdUUID
import com.kunzisoft.keepass.database.element.security.ProtectedString
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import com.kunzisoft.keepass.database.element.CustomDataItem
import java.util.UUID
import com.kunzisoft.keepass.utils.UUIDUtils.asHexString

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class FieldReferencesEngineTest {

    private lateinit var mDatabase: DatabaseKDBX
    private lateinit var mRootGroup: GroupKDBX

    private fun createDatabase(): DatabaseKDBX {
        return DatabaseKDBX("TestDB", "Root")
    }

    private fun addEntryToDatabase(
        title: String = "",
        username: String = "",
        password: CharArray = CharArray(0),
        url: String = "",
        notes: String = "",
        vararg customFields: Pair<String, String>
    ): EntryKDBX {
        val entry = EntryKDBX().apply {
            this.title = title
            this.username = username
            this.password = password
            this.url = url
            this.notes = notes
            customFields.forEach { (name, value) ->
                putField(name, ProtectedString(false, value))
            }
            // Force a deterministic UUID for stable assertions
            nodeId = NodeIdUUID(UUID.fromString("00000000-0000-0000-0000-000000000001"))
        }
        mDatabase.addEntryTo(entry, mRootGroup)
        return entry
    }

    // Replace the UUID so tests that rely on a stable ID don't clash
    private fun addEntryToDatabaseWithUuid(
        uuid: String,
        title: String = "",
        username: String = "",
        password: CharArray = CharArray(0),
        url: String = "",
        notes: String = "",
        vararg customFields: Pair<String, String>
    ): EntryKDBX {
        val entry = EntryKDBX().apply {
            this.title = title
            this.username = username
            this.password = password
            this.url = url
            this.notes = notes
            customFields.forEach { (name, value) ->
                putField(name, ProtectedString(false, value))
            }
            nodeId = NodeIdUUID(UUID.fromString(uuid))
        }
        mDatabase.addEntryTo(entry, mRootGroup)
        return entry
    }

    private fun assertFieldValue(expected: String, actual: CharArray) {
        assertEquals(expected, String(actual))
    }

    // ---------------------------------------------------------------
    // 1. Basic self-reference resolution (S:) in the *same* entry
    // ---------------------------------------------------------------
    @Test
    fun testSelfReferenceTitle() {
        mDatabase = createDatabase()
        mRootGroup = mDatabase.rootGroup!!
        val entry = addEntryToDatabase(
            title = "{S:custom-field}",
            customFields = arrayOf("custom-field" to "resolved-custom-value")
        )
        val resolved = mDatabase.getFieldReferenceValue(entry, entry.title.toCharArray(), 0)
        assertFieldValue("resolved-custom-value", resolved)
    }

    @Test
    fun testSelfReferenceUsername() {
        mDatabase = createDatabase()
        mRootGroup = mDatabase.rootGroup!!
        val entry = addEntryToDatabase(
            username = "{S:custom-field}",
            customFields = arrayOf("custom-field" to "resolved-username")
        )
        val resolved = mDatabase.getFieldReferenceValue(entry, entry.username.toCharArray(), 0)
        assertFieldValue("resolved-username", resolved)
    }

    @Test
    fun testSelfReferencePassword() {
        mDatabase = createDatabase()
        mRootGroup = mDatabase.rootGroup!!
        val entry = addEntryToDatabase(
            password = "{S:custom-field}".toCharArray(),
            customFields = arrayOf("custom-field" to "resolved-password")
        )
        val resolved = mDatabase.getFieldReferenceValue(entry, entry.password, 0)
        assertFieldValue("resolved-password", resolved)
    }

    @Test
    fun testSelfReferenceUrl() {
        mDatabase = createDatabase()
        mRootGroup = mDatabase.rootGroup!!
        val entry = addEntryToDatabase(
            url = "{S:custom-field}",
            customFields = arrayOf("custom-field" to "resolved-url")
        )
        val resolved = mDatabase.getFieldReferenceValue(entry, entry.url.toCharArray(), 0)
        assertFieldValue("resolved-url", resolved)
    }

    @Test
    fun testSelfReferenceNotes() {
        mDatabase = createDatabase()
        mRootGroup = mDatabase.rootGroup!!
        val entry = addEntryToDatabase(
            notes = "{S:custom-field}",
            customFields = arrayOf("custom-field" to "resolved-notes")
        )
        val resolved = mDatabase.getFieldReferenceValue(entry, entry.notes.toCharArray(), 0)
        assertFieldValue("resolved-notes", resolved)
    }

    // ---------------------------------------------------------------
    // 2. Cross-entry REF: resolving fields that contain S: references
    //    (The core bug: target entry is not managed => S: refs leak)
    // ---------------------------------------------------------------

    /**
     * Original bug report scenario:
     * EntryA.title = "{S:custom-field}"
     * EntryA.custom-field = "custom-entry-A-value"
     * EntryB.title = "{REF:T@I:EntryA}"
     * Expected: EntryB.title resolves to "custom-entry-A-value"
     */
    @Test
    fun testRefToTitleContainingSelfRef_byUuid() {
        mDatabase = createDatabase()
        mRootGroup = mDatabase.rootGroup!!
        val entryA = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890ab",
            title = "EntryA",
            customFields = arrayOf("custom-field" to "custom-entry-A-value")
        )
        // Now set the title to contain a self-reference
        entryA.title = "{S:custom-field}"
        mDatabase.updateEntry(entryA)

        val entryB = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890cd",
            title = "{REF:T@I:${entryA.id.asHexString()}}"
        )

        val resolved = mDatabase.getFieldReferenceValue(entryB, entryB.title.toCharArray(), 0)
        assertFieldValue("custom-entry-A-value", resolved)
    }

    @Test
    fun testRefToUsernameContainingSelfRef_byTitle() {
        mDatabase = createDatabase()
        mRootGroup = mDatabase.rootGroup!!
        val entryA = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890ab",
            title = "EntryA",
            username = "{S:custom-field}",
            customFields = arrayOf("custom-field" to "resolved-username")
        )
        val entryB = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890cd",
            title = "{REF:U@T:EntryA}"
        )

        val resolved = mDatabase.getFieldReferenceValue(entryB, entryB.title.toCharArray(), 0)
        assertFieldValue("resolved-username", resolved)
    }

    @Test
    fun testRefToPasswordContainingSelfRef_byUsername() {
        mDatabase = createDatabase()
        mRootGroup = mDatabase.rootGroup!!
        val entryA = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890ab",
            title = "EntryA",
            username = "userA",
            password = "{S:custom-field}".toCharArray(),
            customFields = arrayOf("custom-field" to "resolved-password")
        )
        val entryB = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890cd",
            title = "{REF:P@U:userA}"
        )

        val resolved = mDatabase.getFieldReferenceValue(entryB, entryB.title.toCharArray(), 0)
        assertFieldValue("resolved-password", resolved)
    }

    @Test
    fun testRefToUrlContainingSelfRef_byUuid() {
        mDatabase = createDatabase()
        mRootGroup = mDatabase.rootGroup!!
        val entryA = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890ab",
            title = "EntryA",
            url = "{S:custom-field}",
            customFields = arrayOf("custom-field" to "resolved-url")
        )
        val entryB = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890cd",
            title = "{REF:A@I:${entryA.id.asHexString()}}"
        )

        val resolved = mDatabase.getFieldReferenceValue(entryB, entryB.title.toCharArray(), 0)
        assertFieldValue("resolved-url", resolved)
    }

    @Test
    fun testRefToNotesContainingSelfRef_byUuid() {
        mDatabase = createDatabase()
        mRootGroup = mDatabase.rootGroup!!
        val entryA = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890ab",
            title = "EntryA",
            notes = "{S:custom-field}",
            customFields = arrayOf("custom-field" to "resolved-notes")
        )
        val entryB = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890cd",
            title = "{REF:N@I:${entryA.id.asHexString()}}"
        )

        val resolved = mDatabase.getFieldReferenceValue(entryB, entryB.title.toCharArray(), 0)
        assertFieldValue("resolved-notes", resolved)
    }

    // ---------------------------------------------------------------
    // 3. REF: to custom field via standard-field redirection
    // ---------------------------------------------------------------

    @Test
    fun testRefToTitleRedirectingToCustomField_byPassword() {
        mDatabase = createDatabase()
        mRootGroup = mDatabase.rootGroup!!
        val entryA = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890ab",
            title = "EntryA",
            password = "secret".toCharArray(),
            customFields = arrayOf("pin" to "1234")
        )
        // Redirect title -> custom field
        entryA.title = "{S:pin}"
        mDatabase.updateEntry(entryA)

        val entryB = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890cd",
            title = "{REF:T@P:secret}"
        )

        val resolved = mDatabase.getFieldReferenceValue(entryB, entryB.title.toCharArray(), 0)
        assertFieldValue("1234", resolved)
    }

    // ---------------------------------------------------------------
    // 4. Nested / chained S: references in the target
    // ---------------------------------------------------------------

    @Test
    fun testRefToTitleWithNestedSelfRef() {
        mDatabase = createDatabase()
        mRootGroup = mDatabase.rootGroup!!
        val entryA = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890ab",
            title = "{S:level1}",
            customFields = arrayOf(
                "level1" to "{S:level2}",
                "level2" to "final-value"
            )
        )
        val entryB = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890cd",
            title = "{REF:T@I:${entryA.id.asHexString()}}"
        )

        val resolved = mDatabase.getFieldReferenceValue(entryB, entryB.title.toCharArray(), 0)
        assertFieldValue("final-value", resolved)
    }

    // ---------------------------------------------------------------
    // 5. Multiple S: mixed with literal text in referenced field
    // ---------------------------------------------------------------

    @Test
    fun testRefToTitleWithMultipleSelfRefs() {
        mDatabase = createDatabase()
        mRootGroup = mDatabase.rootGroup!!
        val entryA = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890ab",
            title = "UserName: {S:username} | Password: {S:password}",
            customFields = arrayOf(
                "username" to "Alice",
                "password" to "Secret123"
            )
        )
        val entryB = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890cd",
            title = "{REF:T@I:${entryA.id.asHexString()}}"
        )

        val resolved = mDatabase.getFieldReferenceValue(entryB, entryB.title.toCharArray(), 0)
        assertFieldValue("UserName: Alice | Password: Secret123", resolved)
    }

    // ---------------------------------------------------------------
    // 6. REF:O (custom-data search) where entry title has S:
    // ---------------------------------------------------------------

    @Test
    fun testRefByCustomDataToTitleWithSelfRef() {
        mDatabase = createDatabase()
        mRootGroup = mDatabase.rootGroup!!
        val entryA = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890ab",
            title = "{S:custom-title}",
            customFields = arrayOf("custom-title" to "resolved-by-custom-data")
        )
        entryA.customData.put(CustomDataItem("flag", "yes"))
        mDatabase.updateEntry(entryA)

        val entryB = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890cd",
            title = "{REF:T@O:yes}"
        )

        val resolved = mDatabase.getFieldReferenceValue(entryB, entryB.title.toCharArray(), 0)
        assertFieldValue("resolved-by-custom-data", resolved)
    }

    // ---------------------------------------------------------------
    // 7. Source entry has S: + REF: in same field
    // ---------------------------------------------------------------

    @Test
    fun testSourceEntryHasSelfRefAndTargetIsPlain() {
        mDatabase = createDatabase()
        mRootGroup = mDatabase.rootGroup!!
        val entryA = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890ab",
            title = "PlainTitle"
        )
        val entryB = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890cd",
            title = "{S:prefix} {REF:T@I:${entryA.id.asHexString()}}",
            customFields = arrayOf("prefix" to "PrefixValue")
        )

        val resolved = mDatabase.getFieldReferenceValue(entryB, entryB.title.toCharArray(), 0)
        assertFieldValue("PrefixValue PlainTitle", resolved)
    }

    // ---------------------------------------------------------------
    // 8. All 5 standard fields in target have S: refs; REF: to each
    // ---------------------------------------------------------------
    @Test
    fun testRefToAllStandardFieldsContainingSelfRefs() {
        mDatabase = createDatabase()
        mRootGroup = mDatabase.rootGroup!!
        val entryA = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890ab",
            title = "{S:f1}",
            username = "{S:f2}",
            password = "{S:f3}".toCharArray(),
            url = "{S:f4}",
            notes = "{S:f5}",
            customFields = arrayOf(
                "f1" to "title-val",
                "f2" to "user-val",
                "f3" to "pass-val",
                "f4" to "url-val",
                "f5" to "notes-val"
            )
        )
        val entryB = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890cd",
            title = "{REF:T@I:${entryA.id.asHexString()}}",
            username = "{REF:U@I:${entryA.id.asHexString()}}",
            password = "{REF:P@I:${entryA.id.asHexString()}}".toCharArray(),
            url = "{REF:A@I:${entryA.id.asHexString()}}",
            notes = "{REF:N@I:${entryA.id.asHexString()}}"
        )

        assertFieldValue("title-val", mDatabase.getFieldReferenceValue(entryB, entryB.title.toCharArray(), 0))
        assertFieldValue("user-val", mDatabase.getFieldReferenceValue(entryB, entryB.username.toCharArray(), 0))
        assertFieldValue("pass-val", mDatabase.getFieldReferenceValue(entryB, entryB.password, 0))
        assertFieldValue("url-val", mDatabase.getFieldReferenceValue(entryB, entryB.url.toCharArray(), 0))
        assertFieldValue("notes-val", mDatabase.getFieldReferenceValue(entryB, entryB.notes.toCharArray(), 0))
    }

    // ---------------------------------------------------------------
    // 9. REF:I (UUID) – should return raw UUID, unaffected by S: refs
    // ---------------------------------------------------------------
    @Test
    fun testRefToUuid() {
        mDatabase = createDatabase()
        mRootGroup = mDatabase.rootGroup!!
        val entryA = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890ab",
            title = "{S:custom-field}",
            customFields = arrayOf("custom-field" to "ignored")
        )
        val entryB = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890cd",
            title = "{REF:I@I:${entryA.id.asHexString()}}"
        )

        val resolved = mDatabase.getFieldReferenceValue(entryB, entryB.title.toCharArray(), 0)
        assertFieldValue(entryA.id.asHexString() ?: "", resolved)
    }

    // ---------------------------------------------------------------
    // 10. S: inside target entry's custom field, accessed by REF to
    //     a standard field that contains the custom field name
    // ---------------------------------------------------------------
    @Test
    fun testRefToTitleThatRedirectsToAnotherCustomField() {
        mDatabase = createDatabase()
        mRootGroup = mDatabase.rootGroup!!
        val entryA = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890ab",
            title = "{S:secret-name}",
            customFields = arrayOf(
                "secret-name" to "real-secret"
            )
        )
        val entryB = addEntryToDatabaseWithUuid(
            uuid = "12345678-1234-1234-1234-1234567890cd",
            title = "{REF:T@I:${entryA.id.asHexString()}}"
        )

        val resolved = mDatabase.getFieldReferenceValue(entryB, entryB.title.toCharArray(), 0)
        assertFieldValue("real-secret", resolved)
    }
}

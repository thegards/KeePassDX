/* Throwaway reproduction harness for S:/REF: engine investigation.
 *
 * Documents reproducible failures of FieldReferencesEngine on upstream master
 * (2db52c5fd). Each test prints observed output instead of asserting so the
 * suite stays green while the bugs are triaged. See investigation notes in the
 * PR/branch description.
 */
package com.kunzisoft.keepass.tests.element.entry

import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import com.kunzisoft.keepass.database.element.entry.EntryKDBX
import com.kunzisoft.keepass.database.element.node.NodeIdUUID
import com.kunzisoft.keepass.database.element.security.ProtectedString
import com.kunzisoft.keepass.utils.UUIDUtils.asHexString
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ReproInvestigationTest {

    private lateinit var mDatabase: DatabaseKDBX

    @Before
    fun setUp() {
        mDatabase = DatabaseKDBX("TestDB", "Root")
    }

    /** Hex form used by {REF:...@I:<hex>} placeholders (KeePass byte order). */
    private fun hex(uuid: String): String {
        val u = UUID.fromString(uuid.replaceFirst(
            Regex("^([0-9a-fA-F]{8})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]+)$"),
            "$1-$2-$3-$4-$5"))
        return u.asHexString()!!
    }

    private fun addEntry(
        uuid: String,
        title: String = "",
        username: String = "",
        vararg customFields: Pair<String, String>
    ): EntryKDBX {
        val entry = EntryKDBX().apply {
            this.title = title
            this.username = username
            customFields.forEach { (name, value) ->
                putField(name, ProtectedString(false, value))
            }
            nodeId = NodeIdUUID(UUID.fromString(uuid.replaceFirst(
                Regex("^([0-9a-fA-F]{8})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]+)$"),
                "$1-$2-$3-$4-$5")))
        }
        mDatabase.addEntryTo(entry, mDatabase.rootGroup!!)
        return entry
    }

    /** Decode title the way the app does for the actively managed entry. */
    private fun decodeManagedTitle(entry: EntryKDBX): String {
        entry.startToManageFieldReferences(mDatabase)
        try {
            return String(entry.decodeTitleKey(0))
        } finally {
            entry.stopToManageFieldReferences()
        }
    }

    /** Decode a standard/custom field the way the app does for the managed entry. */
    private fun decodeManagedField(entry: EntryKDBX, label: String): String {
        entry.startToManageFieldReferences(mDatabase)
        try {
            val raw = entry.getFieldValue(label)!!.charArrayValue
            return String(mDatabase.getFieldReferenceValue(entry, raw, 0))
        } finally {
            entry.stopToManageFieldReferences()
        }
    }

    private fun render(s: String): String = s.map { c ->
        if (c.code == 0) "\\0" else c
    }.joinToString("")

    /* H1: EntryA.username = {REF:U@I:B}; B.username = {S:domain}; A and B both
     * have a "domain" custom field. Expected: "target.example.org".
     * Observed on master: the target's raw "{S:domain}" leaks back into A's
     * text, then the next loop pass zeroes it -> all-NUL output.
     */
    @Test
    fun transitiveSViaRefLeaksAndZeroes() {
        addEntry("000000000000000000000000000000BB",
            title = "Target", username = "{S:domain}",
            "domain" to "target.example.org")
        val a = addEntry("000000000000000000000000000000AA",
            title = "Source", username = "{REF:U@I:${hex("000000000000000000000000000000BB")}}",
            "domain" to "WRONG-ENTRY-DOMAIN")
        val decoded = decodeManagedField(a, "UserName")
        println("H1 (expected 'target.example.org'): [${render(decoded)}] len=${decoded.length}")
    }

    /* H2: same but A has NO "domain" custom field. With bug 1 fixed the leak
     * would surface as raw text; with A having a matching field the string
     * version of the engine (pre-refactor) resolved it against A (wrong
     * context). Observed on master: zeros (masked by the zeroing bug).
     */
    @Test
    fun transitiveSWithMissingField() {
        addEntry("000000000000000000000000000000CC",
            title = "Target2", username = "{S:domain}",
            "domain" to "target2.example.org")
        val d = addEntry("000000000000000000000000000000DD",
            title = "Source2", username = "{REF:U@I:${hex("000000000000000000000000000000CC")}}")
        val decoded = decodeManagedField(d, "UserName")
        println("H2 (expected 'target2.example.org'): [${render(decoded)}] len=${decoded.length}")
    }

    /* H3: target found by title where the target's title field itself contains
     * a placeholder. Search compares the RAW stored title against the resolved
     * search query -> target not found -> empty cached value.
     */
    @Test
    fun lookupAgainstPlaceholdingTitleFails() {
        addEntry("000000000000000000000000000000EE",
            title = "{S:label}", username = "userE",
            "label" to "ComputedTitle")
        val f = addEntry("000000000000000000000000000000FF",
            title = "Source3", username = "{REF:U@T:ComputedTitle}")
        val decoded = decodeManagedField(f, "UserName")
        println("H3 (expected 'userE'): [${render(decoded)}] len=${decoded.length}")
    }

    /* H4: two self-references in one field. The second loop iteration's cache
     * pass makes no replacement, returns the SAME array, and the caller's
     * "clear the old array" guard (textValue !== textReference) zeroes it.
     * Observed on master: NUL-filled array.
     */
    @Test
    fun twoSelfReferencesSameFieldZeroed() {
        val g = addEntry("00000000000000000000000000000011",
            title = "{S:one} middle {S:two}",
            username = "",
            "one" to "AA",
            "two" to "BB")
        val decoded = decodeManagedTitle(g)
        println("H4 (expected 'AA middle BB'): [${render(decoded)}] len=${decoded.length}")
    }

    /* H5: an entry title that references itself. The by-title search decodes
     * the candidate entry (the managed source itself) recursively -> the
     * engine re-enters with increasing recursion level until the call stack
     * overflows. Documents the recursion guard gap; run individually.
     */
    @Test
    fun selfReferenceByTitleOverflowsStack() {
        val b = addEntry("00000000000000000000000000000021",
            title = "{REF:T@I:${hex("00000000000000000000000000000021")}}",
            username = "userB")
        val decoded = try {
            decodeManagedTitle(b)
        } catch (t: Throwable) {
            println("H5 threw ${t::class.simpleName}: ${t.message}")
            "THREW"
        }
        println("H5 (expected graceful fallback): [${render(decoded)}]")
    }
}
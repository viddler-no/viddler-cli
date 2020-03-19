<script>
    export let table;
    let showFields = false;
    
    function typeText(field) {
        let t = field.sql_type;
        if (typeof t == 'string') {
            switch (t) {
                case 'Bool': return 'bool';
                case 'Blob': return 'blob';
                case 'Longblob': return 'longblob';
                case 'Mediumblob': return 'mediumblob';
                case 'Tinyblob': return 'tinyblob';
                case 'Double': return 'double';
                case 'Float': return 'float';
                case 'Real': return 'real';
                case 'Text': return 'text';
                case 'Tinytext': return 'tinytext';
                case 'Mediumtext': return 'mediumtext';
                case 'Longtext': return 'longtext';
                case 'Date': return 'date';
                case 'Timestamp': return 'timestamp';
                default: debugger;
            }
        } else if (t.hasOwnProperty('Char')) {
            return 'char(' + t.Char + ')';
        } else if (t.hasOwnProperty('Varchar')) {
            return 'varchar(' + t.Varchar + ')';
        } else if (t.hasOwnProperty('Int')) {
            return 'int(' + t.Int + ')';
        } else if (t.hasOwnProperty('UnsignedInt')) {
            return 'unsigned int(' + t.UnsignedInt + ')';
        } else if (t.hasOwnProperty('Bigint')) {
            return 'bigint(' + t.Bigint + ')';
        } else if (t.hasOwnProperty('UnsignedBigint')) {
            return 'unsigned bigint(' + t.UnsignedBigint + ')';
        } else if (t.hasOwnProperty('Tinyint')) {
            return 'tinyint(' + t.Tinyint + ')';
        } else if (t.hasOwnProperty('UnsignedTinyint')) {
            return 'unsigned tinyint(' + t.UnsignedTinyint + ')';
        } else if (t.hasOwnProperty('DateTime')) {
            return 'datetime';
        } else if (t.hasOwnProperty('Binary')) {
            return 'binary';
        } else if (t.hasOwnProperty('Varbinary')) {
            return 'varbinary';
        } else if (t.hasOwnProperty('Enum')) {
            return 'enum';
        } else if (t.hasOwnProperty('Decimal')) {
            return 'decimal';
        }
        debugger;
    }
</script>

<style>
    .table-name {
        cursor: default;
        padding: 3px;
    }
	.table-fields {
        cursor: default;
        font-size: 90%;
        margin: 2px 0 7px 7px;
        color: #565656;
    }
    .type-text {
        color: #b3b3b3;
    }
</style>

<div class="table-name" on:click={() => showFields = !showFields}>{table.name}</div>
{#if showFields}
    <div class="table-fields">
        {#each Object.entries(table.fields) as [fieldname, field]}
            <div>{fieldname}: <span class="type-text">{typeText(field)}</span></div>
        {/each}
    </div>
{/if}
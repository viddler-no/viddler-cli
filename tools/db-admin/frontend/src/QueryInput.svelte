<script>
    import { createEventDispatcher } from 'svelte';
    let query;
    const dispatch = createEventDispatcher();
    function doQuery() {
        dispatch('query', {
            query
        })
    }
</script>
<style>
    .layout {
        display: flex;
        flex-direction: column;
        height: 100%;
    }
    .query-input {
        flex-grow: 1;
    }
    textarea {
        width: 100%;
        height: 100%;
    }
    .query-button {
        flex-basis: 25px;
    }
    button {
        height: 100%;
    }
</style>
<div class="layout">
    <div class="query-input">
        <textarea bind:value={query}></textarea>
    </div>
    <div class="query-button">
        <button on:click={doQuery}>Query</button>
    </div>
</div>